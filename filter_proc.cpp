#include <limits.h>
#include <regex.h>
#include <stdlib.h>
#include <stdio.h>

#include <signal.h>
#include <sys/ptrace.h>
#include <sys/user.h>

#include "config.h"
#include "filter.h"
#include "jail.h"
#include "memory.h"
#include "report.h"

#include "process_state.h"

using namespace std;

static int regex_init = false;
static regex_t exec_reg;

exec_filter::exec_filter() : fork_count(0), clone_count(0) {
}

exec_filter::~exec_filter() {
}

static filter_action filter_exec(process_state& st) {
  pid_t pid = st.get_pid();
  if(!regex_init) {
    if(regcomp(&exec_reg, get_exec_match().c_str(),
               REG_EXTENDED | REG_NOSUB)) {
      log_violation(pid, "could not compile exec match regex");
      return FILTER_BLOCK_SYSCALL;
    }
    regex_init = true;
  }

  char* filename = (char*)safemem_read_pid_to_null(pid, st.get_param(0));
  if(!filename) {
    log_violation(pid, "could not read exec filename");
    return FILTER_BLOCK_SYSCALL;
  }

  if(regexec(&exec_reg, filename, 0, NULL, 0)) {
    log_violation(pid, "invalid execve filename " + string(filename));
    return FILTER_BLOCK_SYSCALL;
  }

  if(!get_passive()) {
    uintptr_t rem_addr = safemem_remote_addr(pid, filename);
    if(!rem_addr) {
      log_violation(pid, "cannot allow file op without safe mem installed");
      return FILTER_BLOCK_SYSCALL;
    }
    st.set_param(0, rem_addr);
  }

  return FILTER_PERMIT_SYSCALL;
}

filter_action exec_filter::filter_syscall_enter(process_state& st) {
  bool isfork = false;
  switch(st.get_syscall()) {
    case sys_execve:
      return filter_exec(st);

    case sys_fork:
    case sys_vfork:
      isfork = true;

    case sys_clone:
      if(!isfork) {
        /* Force CLONE_PTRACE into the flags. */
        param_t flags = st.get_param(0);
        flags |= CLONE_PTRACE;
        flags &= ~CLONE_UNTRACED;
        st.set_param(0, flags);
        st.save();

        /* This is the same rule that ptrace(2) uses to differentiate between a
         * fork and a clone. */
        isfork = (flags & 0xFF) == SIGCHLD;
      }
      if(isfork && (get_processes() < 0 ||
                    fork_count < (size_t)get_processes())) {
        ++fork_count;
        return FILTER_PERMIT_SYSCALL;
      } else if(!isfork && (get_threads() < 0 ||
                            clone_count < (size_t)get_threads())) {
        ++clone_count;
        return FILTER_PERMIT_SYSCALL;
      }
      return FILTER_BLOCK_SYSCALL;

    default:
      return FILTER_NO_ACTION;
  }
}

filter_action exec_filter::filter_syscall_exit(process_state& st) {
  bool isfork = false;
  switch(st.get_syscall()) {
    case sys_fork:
    case sys_vfork:
      isfork = true;

    case sys_clone:
      if(!isfork) {
        isfork = (st.get_param(0) & 0xFF) == SIGCHLD;
      }
      if(st.is_error_result()) {
        --(isfork ? fork_count : clone_count);
      }
      break;

    default: break;
  }
  return FILTER_NO_ACTION;
}
