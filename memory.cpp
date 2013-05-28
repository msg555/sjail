#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <algorithm>

#include <errno.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <unistd.h>
#include <fcntl.h>

#include "config.h"
#include "sjail.h"
#include "process_state.h"
#include "filter.h"
#include "report.h"
#include "allocator.h"

static const size_t MAPPING_SIZE = 1 << 12;

static int mfd;
static memory_allocator<char> safe_mem_allocator;

bool safemem_init() {
  char buf[16] = "/tmp/XXXXXX";

  int wmfd = mkstemp(buf);
  if(wmfd == -1) {
    return false;
  }
  mfd = open(buf, O_RDONLY);
  if(mfd == -1) {
    return false;
  }
  if(unlink(buf) == -1) {
    return false;
  }
  if(ftruncate(wmfd, MAPPING_SIZE) == -1) {
    return false;
  }

  void* base_addr = mmap(NULL, MAPPING_SIZE, PROT_READ | PROT_WRITE,
                         MAP_SHARED, wmfd, 0);
  if(base_addr == (void*)-1) {
    return false;
  }
  close(wmfd);

  safe_mem_allocator.reset(reinterpret_cast<char*>(base_addr), MAPPING_SIZE);
  return true;
}

bool safemem_map_unwritable() {
  if(munmap(const_cast<void*>(reinterpret_cast<const void*>(
                                            safe_mem_allocator.address())),
            safe_mem_allocator.size())) {
    return false;
  }
  safe_mem_allocator.reset(NULL, 0);
  return true;
}

void* safemem_read_pid(pid_data& pdata, uintptr_t remote_addr, size_t len) {
  char* wptr = safe_mem_allocator.allocate((len + 0x7) * ~0x7);
  if(!wptr) {
    return NULL;
  }
  pdata.allocations.push_back(std::make_pair(wptr, (len + 0x7) & ~0x7));

  for(size_t i = 0; i < len; ) {
    uintptr_t a = (remote_addr + i) & (sizeof(long) - 1);
    uintptr_t b = std::min(sizeof(long), a + len - i);

    errno = 0;
    long v = ptrace(PTRACE_PEEKDATA, pdata.pid, remote_addr + i - a, NULL);
    if(errno == EFAULT) {
      return NULL;
    }

    memcpy(wptr + i, (char *)&v + a, b - a);
    i += b - a;
  }

  return wptr;
}

void* safemem_read_pid_to_null(pid_data& pdata, uintptr_t remote_addr) {
  size_t max_size;
  char* wptr = safe_mem_allocator.allocate_largest(&max_size);
  if(!wptr) {
    return NULL;
  }

  for(size_t i = 0; ; ) {
    uintptr_t a = (remote_addr + i) & (sizeof(long) - 1);

    errno = 0;
    long v = ptrace(PTRACE_PEEKDATA, pdata.pid, remote_addr + i - a, NULL);
    if(errno == EFAULT) {
      return NULL;
    }

    char* vptr = (char*)&v + a;
    for(size_t ie = i + sizeof(long) - a; i != ie; i++, vptr++) {
      if(!(wptr[i] = *vptr)) {
        size_t sz = ((i + 8) & ~0x7);
        safe_mem_allocator.free(wptr + sz, max_size - sz);
        pdata.allocations.push_back(std::make_pair(wptr, sz));
        return wptr;
      } else if(i + 1 == max_size) {
        safe_mem_allocator.free(wptr, max_size);
        return NULL;
      }
    }
  }
}

uintptr_t safemem_remote_addr(pid_data& pdata, void* local_ptr) {
  if(!pdata.safe_mem_base) {
    return 0;
  }
  return pdata.safe_mem_base +
      (reinterpret_cast<const char*>(local_ptr) - safe_mem_allocator.address());
}

static bool install_safe_memory(pid_data& pdata, process_state& st) {
  assert(!get_passive());

  /* Set and store the state that the client will observe after the syscall. */
  st.set_result(-ENOENT);
  pdata.restore_state = new process_state(st);

  /* Write our new syscall. */
  st.set_syscall(sys_mmap);
  st.set_param(0, 0);
  st.set_param(1, MAPPING_SIZE);
  st.set_param(2, PROT_READ);
  st.set_param(3, MAP_SHARED);
  st.set_param(4, mfd);
  st.set_param(5, 0);
  st.save();

  pdata.installing_safe_mem = true;
  return !st.error();
}

static bool install_safe_memory_result(pid_data& pdata, process_state& st) {
  if(st.is_error_result()) {
    return false;
  }

  pdata.safe_mem_base = (uintptr_t)st.get_result();
  pdata.installing_safe_mem = false;
  return true;
}

static bool safemem_filter_mapcall(pid_data& pdata, process_state& st) {
  uintptr_t base = st.get_param(0);
  size_t len = st.get_param(1);
  if(base < pdata.safe_mem_base) {
    return base + len > pdata.safe_mem_base;
  } else {
    return pdata.safe_mem_base + MAPPING_SIZE > base;
  }
}

void safemem_reset(pid_data& pdata) {
  for(auto i : pdata.allocations) {
    safe_mem_allocator.free(i.first, i.second);
  }
  pdata.allocations.clear();
}

static range_tree<unsigned long> read_maps(pid_t pid,
                                           unsigned long page_size) {
  char buf[1024];
  sprintf(buf, "/proc/%u/maps", (unsigned)pid);
  FILE* fmaps = fopen(buf, "r");

  range_tree<unsigned long> mapping;
  for(; fmaps && fgets(buf, sizeof(buf), fmaps); ) {
    unsigned long addr, endaddr;
    if(sscanf(buf, "%lx-%lx %6s", &addr, &endaddr, buf) != 3) {
      break;
    }
    if(buf[1] == 'w') {
      mapping.add(addr / page_size, endaddr / page_size);
    }
  }
  fclose(fmaps);

  return mapping;
}

#ifndef MAP_CONTIG
#define MAP_CONTIG 0x0010
#endif
#ifndef MAP_LOWER16M
#define MAP_LOWER16M 0x0020
#endif
#ifndef MAP_ALIGN64K
#define MAP_ALIGN64K 0x0040
#endif
#ifndef MAP_LOWER1M
#define MAP_LOWER1M 0x0080
#endif

unsigned long memory_filter::page_size = 0;

memory_filter::memory_filter() : heap_base(0), heap_end(0), max_memory(0) {
  if(!page_size) {
    page_size = getpagesize();
  }
}

memory_filter::~memory_filter() {
}

void memory_filter::on_exit(pid_data& pdata, exit_data& data) {
  data.max_mapped_bytes = max_memory * page_size;
}

filter* memory_filter::on_fork() {
  return new memory_filter(*this);
}

filter_action memory_filter::filter_syscall_enter(pid_data& pdata, process_state& st) {
  bool block = false;
  pid_t pid = pdata.pid;
  SYSCALL sys = st.get_syscall();

  if(sys == sys_access && !get_passive() && !pdata.safe_mem_base) {
    /* We hijack an early access call to install our memory mapping. On my
     * system this call always fails anyway.  I'm not sure how portable this
     * technique is. */
    st.set_result(-EPERM);
    pdata.restore_state = new process_state(st);

    if(!install_safe_memory(pdata, st)) {
      log_error(pid, "safe memory installation failed");
      return FILTER_KILL_PID;
    }
    return FILTER_PERMIT_SYSCALL;
  }

  switch(st.get_syscall()) {
    case sys_brk: {
      if(!heap_base && st.get_param(0)) {
        log_error(pid, "moving program break without querying first");
        return FILTER_KILL_PID;
      }
    } break;

    case sys_mmap: {
      /* In particular, MAP_FIXED is not ok as it could allow our safe memory to
       * be evicted. */
      /* If locking pages is ok add MAP_LOCKED. */
      /* Also didn't add MAP_UNINITIALIZED though since most kernels don't honor
       * maybe we should add for compatability. */
      int vetted_flags = MAP_SHARED | MAP_PRIVATE | MAP_ANONYMOUS |
                         MAP_GROWSDOWN | MAP_HUGETLB | MAP_NONBLOCK |
                         MAP_NORESERVE | MAP_POPULATE | MAP_STACK |
                         MAP_CONTIG;
      /* These flags are OK because they don't actually do anything anymore. */
      vetted_flags |= MAP_DENYWRITE | MAP_EXECUTABLE | MAP_FILE;
#ifdef MAP_32BIT
      vetted_flags |= MAP_32BIT;
#endif
      block = (st.get_param(3) & ~vetted_flags) != 0;
      if(block) {
        log_violation(pid, "illegal mmap flags");
      }
    } break;

    case sys_mprotect:
    case sys_munmap:
      block = safemem_filter_mapcall(pdata, st);
      if(block) {
        log_violation(pid, "mprotect/munmap called on safe mem");
      }
      break;

    case sys_close:
      /* We need to protect mfd for future execs. */
      if(st.get_param(0) == (param_t)mfd) {
        return FILTER_BLOCK_SYSCALL;
      } else {
        return FILTER_NO_ACTION;
      }

    default:
      return FILTER_NO_ACTION;
  }
  return block ? FILTER_BLOCK_SYSCALL : FILTER_PERMIT_SYSCALL;
}

filter_action memory_filter::filter_syscall_exit(pid_data& pdata, process_state& st) {
  /* Handle the result of a safe memory installation. */
  pid_t pid = pdata.pid;
  enum SYSCALL sys = st.get_syscall();
  if(pdata.installing_safe_mem) {
    if(sys != sys_mmap) {
      log_error(pid, "installing safe mem but didn't get mmap exit");
      return FILTER_KILL_PID;
    }
    if(!install_safe_memory_result(pdata, st)) {
      log_error(pid, "safe memory installation failed");
      return FILTER_KILL_PID;
    }
    log_info(pid, 2, "safe memory installed");
  }

  if(sys == sys_execve && !st.is_error_result()) {
    heap_base = heap_end = 0;
    //max_memory = 0;
    mappings.clear();
  }
  if(mappings.size() == 0) {
    mappings = read_maps(st.get_pid(), page_size);
    if(mappings.size() == 0) {
      log_error(pid, "could not read memory mappings");
      return FILTER_KILL_PID;
    }
  }

  switch(sys) {
    case sys_brk: {
      if(!st.is_error_result()) {
        unsigned long new_heap_end = st.get_result() / page_size;
        if(!heap_base) {
          log_info(pid, 4, "got heap base");
          heap_base = new_heap_end;
        } else if(new_heap_end < heap_end) {
          mappings.rem(new_heap_end, heap_end);
        } else {
          mappings.add(heap_end, new_heap_end);
        }
        heap_end = new_heap_end;
      }
    } break;
    case sys_mmap: {
      if(!st.is_error_result()) {
        unsigned long map_base = st.get_result() / page_size;
        unsigned long map_len = st.get_param(1) / page_size;
        mappings.add(map_base, map_base + map_len);
      }
    } break;
    case sys_munmap: {
      if(!st.is_error_result()) {
        unsigned long map_base = st.get_param(0) / page_size;
        unsigned long map_len = st.get_param(1) / page_size;
        mappings.rem(map_base, map_base + map_len);
      }
    } break;
    default: break;
  }
  max_memory = std::max(max_memory, mappings.size());
  if(!get_passive() && get_mem() &&
     max_memory * page_size > get_mem() * 1024UL) {
    log_violation(pid, "memory limit exceeded");
    return FILTER_KILL_PID;
  }

  return FILTER_NO_ACTION;
}
