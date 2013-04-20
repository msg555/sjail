#ifndef PROCESS_STATE_H
#define PROCESS_STATE_H

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/param.h>

#include "linux/syscall_tab.h"

#ifdef __i386__
# define I386
#endif

#ifdef __x86_64__
# ifdef __ILP32__
#  define X32
# else
#  define X86_64
# endif
#endif

typedef unsigned long param_t;

void init_process_state();

class process_state {
 public:
  process_state(pid_t pid);

  enum SYSCALL get_syscall();
  void set_syscall(enum SYSCALL sys);

  const char* get_syscall_name(enum SYSCALL sys);
  bool is_error_result();

  param_t get_result();
  void set_result(param_t v);

  param_t get_param(size_t i);
  void set_param(size_t i, param_t val);

  pid_t get_pid();

  int error();
  void save();

  size_t word_width();
  param_t read_uword(void* addr);
  void write_uword(void* addr, param_t v);

 private:
  pid_t pid;
  int error_state;
  size_t pers;
#if defined(I386)
  struct user_regs_struct i386_regs;
#elif defined(X32) || defined(X86_64)
  struct user_regs_struct x86_64_regs;
#else
  #error "unknown architecture"
#endif
};

#endif // PROCESS_STATE_H
