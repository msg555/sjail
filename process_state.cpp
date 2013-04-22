#include "process_state.h"

#include <stdio.h>
#include <string.h>

#define NF 0
#define TD 0
#define TF 0
#define TI 0
#define TN 0
#define TP 0
#define TS 0

struct sysent {
  size_t nargs;
  int sys_flags;
  enum SYSCALL sysid;
  const char *sys_name;
};

/* All of the modes we support have the same error table.  If we support more in
 * the future this may need to change.  As of writing this, this number is only
 * used to determine if a result from a syscall is an error. */
static size_t nerrnos = 531;

#if defined(I386)

static unsigned long scno_tab0[NUM_SYSCALLS];
static const struct sysent sysent0[] = {
#include "linux/i386/syscallent.h"
};

#elif defined(X32)
#define HAVE_SYSENT1

static unsigned long scno_tab0[NUM_SYSCALLS];
static const struct sysent sysent0[] = {
#include "linux/x32/syscallent.h"
};

static unsigned long scno_tab1[NUM_SYSCALLS];
static const struct sysent sysent1[] = {
#include "linux/x32/syscallent1.h"
};

#elif defined(X86_64)
#define HAVE_SYSENT1
#define HAVE_SYSENT2

static unsigned long scno_tab0[NUM_SYSCALLS];
static const struct sysent sysent0[] = {
#include "linux/x86_64/syscallent.h"
};

static unsigned long scno_tab1[NUM_SYSCALLS];
static const struct sysent sysent1[] = {
#include "linux/x86_64/syscallent1.h"
};

static unsigned long scno_tab2[NUM_SYSCALLS];
static const struct sysent sysent2[] = {
#include "linux/x86_64/syscallent2.h"
};

#else
#error "unknown architecture"
#endif

void init_process_state() {
  size_t i;
  memset(scno_tab0, -1, sizeof(scno_tab0));
  for(i = 0; i < sizeof(sysent0) / sizeof(sysent); i++) {
    scno_tab0[sysent0[i].sysid] = i;
  }
#ifdef HAVE_SYSENT1
  memset(scno_tab1, -1, sizeof(scno_tab1));
  for(i = 0; i < sizeof(sysent1) / sizeof(sysent); i++) {
    scno_tab1[sysent1[i].sysid] = i;
  }
#endif
#ifdef HAVE_SYSENT2
  memset(scno_tab2, -1, sizeof(scno_tab2));
  for(i = 0; i < sizeof(sysent2) / sizeof(sysent); i++) {
    scno_tab2[sysent2[i].sysid] = i;
  }
#endif
}

process_state::process_state(pid_t pid) : pid(pid), error_state(0), pers(0) {
  long res;
#if defined(I386)
  res = ptrace(PTRACE_GETREGS, pid, NULL, &i386_regs);
#else
  res = ptrace(PTRACE_GETREGS, pid, NULL, &x86_64_regs);
#endif
  if(res) {
    error_state |= 1;
    return;
  }

#if defined(X86_64) || defined(X32)
  /* Check CS register value. On x86-64 linux it is:
   *  0x33  for long mode (64 bit)
   *  0x23  for compatibility mode (32 bit)
   * Check DS register value. On x86-64 linux it is:
   *  0x2b  for x32 mode (x86-64 in 32 bit)
   */
  switch (x86_64_regs.cs) {
    case 0x23: pers = 1; break;
    case 0x33:
      if (x86_64_regs.ds == 0x2b) {
        pers = 2;
      } else {
        pers = 0;
      }
      break;
    default:
      fprintf(stderr, "Unknown execution mode\n");
      error_state |= 1;
      return;
  }
# ifdef X32
  /* Value of pers:
   *   0: 64 bit
   *   1: 32 bit
   *   2: X32
   * Transform to:
   *   0: X32
   *   1: 32 bit
   */
  switch (pers) {
    case 0:
      fprintf(stderr, "64-bit mode not supported for x32 jail\n");
      error_state |= 1;
      break;
    case 2:
      pers = 0;
      break;
  }
# endif
#endif
}

enum SYSCALL process_state::get_syscall() {
  unsigned long scno;

#if defined(I386)
  scno = i386_regs.orig_eax;
#else
# ifndef __X32_SYSCALL_BIT
#  define __X32_SYSCALL_BIT 0x40000000
# endif
# ifndef __X32_SYSCALL_MASK
#  define __X32_SYSCALL_MASK  __X32_SYSCALL_BIT
# endif
  scno = x86_64_regs.orig_rax;
  if(x86_64_regs.cs == 0x33 && x86_64_regs.ds == 0x2b) {
    scno &= ~__X32_SYSCALL_MASK;
  }
#endif

  if(pers == 0) {
    if(scno < sizeof(sysent0) / sizeof(sysent)) {
      return sysent0[scno].sysid;
    } else {
      error_state |= 1;
      fprintf(stderr, "Bad syscall number\n");
      return sys_none;
    }
#ifdef HAVE_SYSENT1
  } else if(pers == 1) {
    if(scno < sizeof(sysent1) / sizeof(sysent)) {
      return sysent1[scno].sysid;
    } else {
      error_state |= 1;
      fprintf(stderr, "Bad syscall number\n");
      return sys_none;
    }
#endif
#ifdef HAVE_SYSENT2
  } else if(pers == 2) {
    if(scno < sizeof(sysent2) / sizeof(sysent)) {
      return sysent2[scno].sysid;
    } else {
      error_state |= 1;
      fprintf(stderr, "Bad syscall number\n");
      return sys_none;
    }
#endif
  } else {
    error_state |= 1;
    fprintf(stderr, "Bad personality\n");
    return sys_none;
  }
}

void process_state::set_syscall(enum SYSCALL sys) {
  unsigned long scno;
  if(pers == 0) {
    scno = scno_tab0[sys];
#ifdef HAVE_SYSENT1
  } else if(pers == 1) {
    scno = scno_tab1[sys];
#endif
#ifdef HAVE_SYSENT2
  } else if(pers == 2) {
    scno = scno_tab2[sys];
#endif
  } else {
    error_state |= 1;
    fprintf(stderr, "Bad personality\n");
    return;
  }
  if((long)scno == -1) {
    error_state |= 1;
    fprintf(stderr, "No syscall on architecture\n");
    return;
  }

#if defined(I386)
  i386_regs.orig_eax = scno;
#else
# ifndef __X32_SYSCALL_BIT
#  define __X32_SYSCALL_BIT 0x40000000
# endif
# ifndef __X32_SYSCALL_MASK
#  define __X32_SYSCALL_MASK  __X32_SYSCALL_BIT
# endif
  if(x86_64_regs.cs == 0x33 && x86_64_regs.ds == 0x2b) {
    x86_64_regs.orig_rax = (x86_64_regs.orig_rax & __X32_SYSCALL_MASK) | scno;
  } else {
    x86_64_regs.orig_rax = scno;
  }
#endif
}

size_t process_state::get_num_params(SYSCALL sys) {
  if(pers == 0) {
    if(scno_tab0[sys] != (unsigned long)-1) {
      return sysent0[scno_tab0[sys]].nargs;
    }
#ifdef HAVE_SYSENT1
  } else if(pers == 1) {
    if(scno_tab1[sys] != (unsigned long)-1) {
      return sysent1[scno_tab1[sys]].nargs;
    }
#endif
#ifdef HAVE_SYSENT2
  } else if(pers == 2) {
    if(scno_tab2[sys] != (unsigned long)-1) {
      return sysent2[scno_tab2[sys]].nargs;
    }
#endif
  } else {
    error_state |= 1;
    fprintf(stderr, "Bad personality\n");
    return 0U;
  }
  error_state |= 1;
  fprintf(stderr, "No syscall on architecture\n");
  return 0U;
}

const char* process_state::get_syscall_name(SYSCALL sys) {
  if(pers == 0) {
    if(scno_tab0[sys] != (unsigned long)-1) {
      return sysent0[scno_tab0[sys]].sys_name;
    }
#ifdef HAVE_SYSENT1
  } else if(pers == 1) {
    if(scno_tab1[sys] != (unsigned long)-1) {
      return sysent1[scno_tab1[sys]].sys_name;
    }
#endif
#ifdef HAVE_SYSENT2
  } else if(pers == 2) {
    if(scno_tab2[sys] != (unsigned long)-1) {
      return sysent2[scno_tab2[sys]].sys_name;
    }
#endif
  } else {
    error_state |= 1;
    fprintf(stderr, "Bad personality\n");
    return NULL;
  }
  error_state |= 1;
  fprintf(stderr, "No syscall on architecture\n");
  return NULL;
}

bool process_state::is_error_result() {
  param_t val = get_result();
  param_t max = -(long int) nerrnos;
#if defined(X86_64)
  if (pers != 0) {
    val = (unsigned int) val;
    max = (unsigned int) max;
  }
#endif
  return val > max;
}

param_t process_state::get_result() {
#if defined(I386)
  return i386_regs.eax;
#else
  if(pers == 1) {
    return (unsigned int)x86_64_regs.rax;
  } else {
    return x86_64_regs.rax;
  }
#endif
}

void process_state::set_result(param_t v) {
#if defined(I386)
  i386_regs.eax = v;
#else
  x86_64_regs.rax = v;
#endif
}

param_t process_state::get_param(size_t i) {
#if defined(I386)
  switch(i) {
    case 0: return i386_regs.ebx;
    case 1: return i386_regs.ecx;
    case 2: return i386_regs.edx;
    case 3: return i386_regs.esi;
    case 4: return i386_regs.edi;
    case 5: return i386_regs.ebp;
  }
#else
  if(pers == 1) {
    switch(i) {
      /* i386 ABI */
      case 0: return (unsigned int)x86_64_regs.rbx;
      case 1: return (unsigned int)x86_64_regs.rcx;
      case 2: return (unsigned int)x86_64_regs.rdx;
      case 3: return (unsigned int)x86_64_regs.rsi;
      case 4: return (unsigned int)x86_64_regs.rdi;
      case 5: return (unsigned int)x86_64_regs.rbp;
    }
  } else switch(i) {
    case 0: return x86_64_regs.rdi;
    case 1: return x86_64_regs.rsi;
    case 2: return x86_64_regs.rdx;
    case 3: return x86_64_regs.r10;
    case 4: return x86_64_regs.r8;
    case 5: return x86_64_regs.r9;
  }
#endif

  fprintf(stderr, "bad parameter index\n");
  return 0;
}

void process_state::set_param(size_t i, param_t val) {
#if defined(I386)
  switch(i) {
    case 0: i386_regs.ebx = val; break;
    case 1: i386_regs.ecx = val; break;
    case 2: i386_regs.edx = val; break;
    case 3: i386_regs.esi = val; break;
    case 4: i386_regs.edi = val; break;
    case 5: i386_regs.ebp = val; break;
    default:
      error_state |= 1;
      fprintf(stderr, "bad parameter index\n");
  }
#else
  if(pers == 1) {
    /* i386 ABI */
    unsigned long I386ABI_MASK = 0xFFFFFFFF00000000UL;
    unsigned int v = (unsigned int)val;
    switch(i) {
      case 0: x86_64_regs.rbx = (x86_64_regs.rbx & I386ABI_MASK) | v; break;
      case 1: x86_64_regs.rcx = (x86_64_regs.rcx & I386ABI_MASK) | v; break;
      case 2: x86_64_regs.rdx = (x86_64_regs.rdx & I386ABI_MASK) | v; break;
      case 3: x86_64_regs.rsi = (x86_64_regs.rsi & I386ABI_MASK) | v; break;
      case 4: x86_64_regs.rdi = (x86_64_regs.rdi & I386ABI_MASK) | v; break;
      case 5: x86_64_regs.rbp = (x86_64_regs.rbp & I386ABI_MASK) | v; break;
      default:
        error_state |= 1;
        fprintf(stderr, "bad parameter index\n");
    }
  } else switch(i) {
    case 0: x86_64_regs.rdi = val; break;
    case 1: x86_64_regs.rsi = val; break;
    case 2: x86_64_regs.rdx = val; break;
    case 3: x86_64_regs.r10 = val; break;
    case 4: x86_64_regs.r8 = val; break;
    case 5: x86_64_regs.r9 = val; break;
    default:
      error_state |= 1;
      fprintf(stderr, "bad parameter index\n");
  }
#endif
}

pid_t process_state::get_pid() {
  return pid;
}

int process_state::error() {
  return error_state;
}

void process_state::save() {
#if defined(I386)
  long res = ptrace(PTRACE_SETREGS, pid, NULL, &i386_regs);
#else
  long res = ptrace(PTRACE_SETREGS, pid, NULL, &x86_64_regs);
#endif
  error_state |= res != 0;
}

size_t process_state::word_width() {
#if defined(I386)
  return sizeof(param_t);
#else
  return pers == 1 ? sizeof(unsigned int) : sizeof(param_t);
#endif
}

param_t process_state::read_uword(void* addr) {
#if defined(I386)
  return *(param_t*)addr;
#else
  return pers == 1 ? *(unsigned int*)addr : *(param_t*)addr;
#endif
}

void process_state::write_uword(void* addr, param_t v) {
#if defined(I386)
  *(param_t*)addr = v;
#else
  if(pers == 1) {
    *(unsigned int*)addr = (unsigned int)v;
  } else {
    *(param_t*)addr = v;
  }
#endif
}
