#include <iostream>
#include <map>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <regex.h>
#include <linux/net.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "config.h"
#include "filter.h"
#include "signal_tab.h"
#include "report.h"
#include "jail.h"
#include "memory.h"

#include "process_state.h"

#include <cstdio>

static bool first_call = true;

static filter_action filter_syscall_enter(process_state& st) {
  bool block = false;
  bool permit = false;
  bool save = false;
  pid_t pid = st.get_pid();
  for(std::list<filter*>::iterator it = proc[pid].filters.begin();
      it != proc[pid].filters.end() && !block && !permit; it++) {
    switch((*it)->filter_syscall_enter(st)) {
      case FILTER_KILL_PID: return FILTER_KILL_PID;
      case FILTER_KILL_ALL: return FILTER_KILL_ALL;
      case FILTER_BLOCK_SYSCALL: save = block = true; break;
      case FILTER_PERMIT_SYSCALL: permit = true; break;
      case FILTER_CHANGED_SYSCALL: save = true; break;
    }
  }
  block |= !permit;

  if(get_report() && get_log_level() >= 5) {
    log_info(pid, 5, std::string("syscall ") +
              st.get_syscall_name(st.get_syscall()));
  }

  if(save) {
    st.set_result(-EPERM);
    proc[pid].restore_state = new process_state(st);
  }

  if(block && !get_passive()) {
    log_blocked_syscall(st);
    st.set_syscall(sys_getpid);
    st.save();
    if(st.error()) {
      log_error(pid, "failed to block syscall");
      return FILTER_KILL_PID;
    }
  }

  return FILTER_NO_ACTION;
}

static filter_action filter_syscall_exit(process_state& st) {
  pid_t pid = st.get_pid();
  SYSCALL sys = st.get_syscall();

  for(std::list<filter*>::iterator it = proc[pid].filters.begin();
      it != proc[pid].filters.end(); it++) {
    switch((*it)->filter_syscall_exit(st)) {
      case FILTER_KILL_PID: return FILTER_KILL_PID;
      case FILTER_KILL_ALL: return FILTER_KILL_ALL;
    }
  }

  if(proc[pid].restore_state) {
    st = *proc[pid].restore_state;
    delete proc[pid].restore_state;
    proc[pid].restore_state = NULL;

    st.save();
    if(st.error()) {
      return FILTER_KILL_PID;
    }
  }

  return FILTER_NO_ACTION;
}

filter_action filter_system_call(pid_t pid) {
  process_state st(pid);
  if(st.error()) {
    log_error(pid, "ptrace_getregs failed");
    return FILTER_KILL_PID;
  }

  /* We expect the very first filtered system call to be execve. */
  if(first_call) {
    /* TODO: I'm not totally sure what happens when the execution mode of jail
     * and the execution mode of the client process don't match on this first
     * exec.  For now we'll just assume nothing went wrong and the first result
     * is alwasy from exec. */
		if(true || st.get_syscall() == sys_execve) {
      first_call = false;
			proc[pid].enter_call = false;
      return FILTER_NO_ACTION;
		}

    log_error(pid, "first system call not execve");
    return FILTER_KILL_ALL;
  }

  safemem_reset();

  filter_action action;
  proc[pid].enter_call = !proc[pid].enter_call;
  if(proc[pid].enter_call) {
    action = filter_syscall_enter(st);
  } else {
    action = filter_syscall_exit(st);
  }

  return action;
}

std::list<filter*> create_root_filters() {
  std::list<filter*> filters;
  filters.push_back(new memory_filter());
  if(!get_files().empty()) {
    filters.push_back(new file_filter());
  }
  if(!get_exec_match().empty()) {
    filters.push_back(new exec_filter());
  }
  if(get_net()) {
    filters.push_back(new net_filter());
  }
  filters.push_back(new base_filter());
  return filters;
}

std::list<filter*> clone_filters(const std::list<filter*>& filters) {
  std::list<filter*> res;
  for(std::list<filter*>::const_iterator it = filters.begin();
      it != filters.end(); it++) {
    res.push_back((*it)->on_clone());
  }
  return res;
}

std::list<filter*> fork_filters(const std::list<filter*>& filters) {
  std::list<filter*> res;
  for(std::list<filter*>::const_iterator it = filters.begin();
      it != filters.end(); it++) {
    res.push_back((*it)->on_fork());
  }
  return res;
}

filter::filter() : refs(1) {
}

filter::~filter() {
}

filter* filter::ref() {
  ++refs;
  return this;
}

bool filter::unref() {
  return --refs == 0;
}

void filter::on_exit(pid_t pid) {
}

filter* filter::on_clone() {
  return ref();
}

filter* filter::on_fork() {
  return ref();
}

filter_action filter::filter_syscall_enter(process_state& st) {
  return FILTER_NO_ACTION;
}

filter_action filter::filter_syscall_exit(process_state& st) {
  return FILTER_NO_ACTION;
}

base_filter::base_filter() {
}

base_filter::~base_filter() {
}

filter_action base_filter::filter_syscall_enter(process_state& st) {
  switch(st.get_syscall()) {
    case sys_brk: break;

    case sys_exit: break;
    case sys_exit_group: break;

    case sys_close: break;

    case sys_read:
    case sys_write:
    case sys_readv:
    case sys_writev:
    case sys_preadv:
    case sys_pwritev:
      break;

    case sys_arch_prctl:
    case sys_set_thread_area:
    case sys_get_thread_area:
      break;

    case sys_getpid:
    case sys_getppid:
    case sys_getuid:
    case sys_geteuid:
    case sys_getresuid:
    case sys_getgid:
    case sys_getegid:
    case sys_getresgid:
      break;

    default:
      return FILTER_NO_ACTION;
  }
  return FILTER_PERMIT_SYSCALL;
}
