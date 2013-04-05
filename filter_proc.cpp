#include <limits.h>
#include <regex.h>
#include <stdlib.h>

#include <sys/ptrace.h>
#include <sys/user.h>

#include "config.h"
#include "filter.h"
#include "jail.h"
#include "memory.h"
#include "report.h"

static regex_t exec_reg;

bool filter_proc_init() {
  return get_exec_match().empty() ||
     !regcomp(&exec_reg, get_exec_match().c_str(), REG_EXTENDED | REG_NOSUB);
}

bool filter_exec(pid_t pid, user_regs_struct& reg,
                 unsigned long param1, unsigned long param2,
                 unsigned long param3) {
  char* filename = (char*)read_from_pid_to_null(pid, param1);

  if(!filename) {
    log_violation(pid, "could not read execve filename");
    return false;
  }

  if(get_exec_match().empty()) {
    log_violation(pid, "execve disabled");
    return false;
  } else if(regexec(&exec_reg, filename, 0, NULL, 0)) {
    log_violation(pid, "invalid execve filename " + string(filename));
    return false;
  }

  if(!get_passive()) {
    if(!proc[pid].safe_mem_base) {
      log_violation(pid, "cannot allow execve without safe mem installed");
      return false;
    }

    #ifdef __x86_64__
    reg.rdi = (unsigned long)proc_safe_memory(pid, filename);
    #endif
    #ifdef __i386__
    reg.ebx = (long)proc_safe_memory(pid, filename);
    #endif
    ptrace(PTRACE_SETREGS, pid, NULL, &reg);
  }

  return true;
}
