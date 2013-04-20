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

#include "process_state.h"

using namespace std;

static int regex_init = false;
static regex_t exec_reg;

exec_filter::exec_filter() {
}

exec_filter::~exec_filter() {
}

filter_action exec_filter::filter_syscall_enter(process_state& st) {
  if(st.get_syscall() != sys_execve) {
    return FILTER_NO_ACTION;
  }

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
