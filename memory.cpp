#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>

#include <errno.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <unistd.h>
#include <fcntl.h>

#include "config.h"
#include "jail.h"
#include "process_state.h"
#include "filter.h"
#include "report.h"

static const size_t MAPPING_SIZE = 1 << 12;

static int mfd;
static void* addr;

bool initialize_safe_memory() {
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

  addr = mmap(NULL, MAPPING_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, wmfd, 0);
  if(addr == (void*)-1) {
    return false;
  }
  close(wmfd);

  return true;
}

bool map_memory_unwritable() {
  if(munmap(addr, MAPPING_SIZE)) {
    return false;
  }
  return true;
}

void* read_from_pid(pid_t pid, intptr_t remote_addr, size_t len) {
  if(len > MAPPING_SIZE) {
    return NULL;
  }

  for(size_t i = 0; i < len; ) {
    intptr_t a = (remote_addr + i) & (sizeof(long) - 1);
    intptr_t b = std::min(sizeof(long), a + len - i);

    errno = 0;
    long v = ptrace(PTRACE_PEEKDATA, pid, remote_addr + i - a, NULL);
    if(errno == EFAULT) {
      return NULL;
    }

    memcpy((char*)addr + i, (char *)&v + a, b - a);
    i += b - a;
  }

  msync(addr, len, MS_SYNC | MS_INVALIDATE);
  return addr;
}

void* read_from_pid_to_null(pid_t pid, intptr_t remote_addr) {
  char* wptr = (char*)addr;
  for(size_t i = 0; ; ) {
    intptr_t a = (remote_addr + i) & (sizeof(long) - 1);

    errno = 0;
    long v = ptrace(PTRACE_PEEKDATA, pid, remote_addr + i - a, NULL);
    if(errno == EFAULT) {
      return NULL;
    }

    char* vptr = (char*)&v + a;
    for(size_t ie = i + sizeof(long) - a; i != ie; i++, vptr++) {
      if(!(wptr[i] = *vptr)) {
        msync(addr, i + 1, MS_SYNC | MS_INVALIDATE);
        return addr;
      } else if(i + 1 == MAPPING_SIZE) {
        return NULL;
      }
    }
  }
}

bool install_safe_memory(pid_t pid, process_state& st) {
  assert(!get_passive());

  /* Set and store the state that the client will observe after the syscall. */
  st.set_result(-ENOENT);
  proc[pid].restore_state = new process_state(st);

  /* Write our new syscall. */
  st.set_syscall(sys_mmap);
  st.set_param(0, 0);
  st.set_param(1, MAPPING_SIZE);
  st.set_param(2, PROT_READ);
  st.set_param(3, MAP_SHARED);
  st.set_param(4, mfd);
  st.set_param(5, 0);
  st.save();

  proc[pid].installing_safe_mem = true;
  return !st.error();
}

bool install_safe_memory_result(pid_t pid, process_state& st) {
  if(st.is_error_result()) {
    return false;
  }

  proc[pid].safe_mem_base = (uintptr_t)st.get_result();
  proc[pid].installing_safe_mem = false;
  return true;
}

intptr_t proc_safe_memory(pid_t pid, void* local_ptr) {
  if(!proc[pid].safe_mem_base) return 0;
  return proc[pid].safe_mem_base + (intptr_t)((char*)local_ptr - (char*)addr);
}

bool safemem_filter_mapcall(process_state& st) {
  pid_t pid = st.get_pid();
  intptr_t base = st.get_param(0);
  size_t len = st.get_param(1);
  if(base < proc[pid].safe_mem_base) {
    return base + len > proc[pid].safe_mem_base;
  } else {
    return proc[pid].safe_mem_base + MAPPING_SIZE > base;
  }
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

memory_filter::memory_filter() {
}

memory_filter::~memory_filter() {
}

filter* memory_filter::on_fork() {
  return new memory_filter(*this);
}

filter_action memory_filter::filter_syscall_enter(process_state& st) {
  bool block = false;
  pid_t pid = st.get_pid();
  SYSCALL sys = st.get_syscall();

  if(sys == sys_access && !get_passive() && !proc[pid].safe_mem_base) {
    /* We hijack an early access call to install our memory mapping. On my
     * system this call always fails anyway.  I'm not sure how portable this
     * technique is. */
    st.set_result(-EPERM);
    proc[pid].restore_state = new process_state(st);

    if(!install_safe_memory(pid, st)) {
      log_error(pid, "safe memory installation failed");
      return FILTER_KILL_PID;
    }
    return FILTER_PERMIT_SYSCALL;
  }

  if(sys == sys_execve) {
    /* TODO: Clear memory information. */
  }

  switch(st.get_syscall()) {
    case sys_brk: break;

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
      block = safemem_filter_mapcall(st);
      if(block) {
        log_violation(pid, "mprotect/munmap called on safe mem");
      }
      break;

    default:
      return FILTER_NO_ACTION;
  }
  return block ? FILTER_BLOCK_SYSCALL : FILTER_PERMIT_SYSCALL;
}

filter_action memory_filter::filter_syscall_exit(process_state& st) {
  /* Handle the result of a safe memory installation. */
  pid_t pid = st.get_pid();
  enum SYSCALL sys = st.get_syscall();
  if(proc[pid].installing_safe_mem) {
    if(sys != sys_mmap) {
      log_error(pid, "installing safe mem but didn't get mmap exit");
      return FILTER_KILL_PID;
    }
    if(!install_safe_memory_result(pid, st)) {
      log_error(pid, "safe memory installation failed");
      return FILTER_KILL_PID;
    }
    log_info(pid, 2, "safe memory installed");
  }
}
