#include <string>

#include <errno.h>
#include <stdlib.h>
#include <sys/time.h>

#include "config.h"
#include "filter.h"
#include "sjail.h"
#include "memory.h"
#include "process_state.h"
#include "report.h"

static bool first_call = true;

static filter_action filter_syscall_enter(pid_data& pdata, process_state& st) {
  if(get_report() && get_log_level() >= 5) {
    log_info(pdata.pid, 5, std::string("syscall ") +
             st.get_syscall_name(st.get_syscall()));
  }

  bool block = false;
  bool permit = false;
  bool save = false;
  for(auto i = pdata.filters.begin();
      i != pdata.filters.end() && !block && !permit; ++i) {
    switch((*i)->filter_syscall_enter(pdata, st)) {
      case FILTER_KILL_PID: return FILTER_KILL_PID;
      case FILTER_KILL_ALL: return FILTER_KILL_ALL;
      case FILTER_BLOCK_SYSCALL: save = block = true; break;
      case FILTER_PERMIT_SYSCALL: permit = true; break;
      case FILTER_CHANGED_SYSCALL: save = true; break;
      default: break;
    }
  }
  block |= !permit;

  if(save && !get_passive()) {
    st.set_result(-EPERM);
    pdata.restore_state = new process_state(st);
  }

  if(block && !get_passive()) {
    log_blocked_syscall(st);
    st.set_syscall(sys_getpid);
    st.save();
    if(st.error()) {
      log_error(pdata.pid, "failed to block syscall");
      return FILTER_KILL_PID;
    }
  }

  return FILTER_NO_ACTION;
}

static filter_action filter_syscall_exit(pid_data& pdata, process_state& st) {
  for(auto i : pdata.filters) {
    switch(i->filter_syscall_exit(pdata, st)) {
      case FILTER_KILL_PID: return FILTER_KILL_PID;
      case FILTER_KILL_ALL: return FILTER_KILL_ALL;
      default: break;
    }
  }

  if(pdata.restore_state) {
    st = *pdata.restore_state;
    delete pdata.restore_state;
    pdata.restore_state = NULL;

    st.save();
    if(st.error()) {
      return FILTER_KILL_PID;
    }
  }

  return FILTER_NO_ACTION;
}

filter_action filter_system_call(pid_data& pdata) {
  process_state st(pdata.pid);
  if(st.error()) {
    log_error(pdata.pid, "ptrace_getregs failed");
    return get_passive() ? FILTER_NO_ACTION : FILTER_KILL_PID;
  }

  /* We expect the very first filtered system call to be execve. */
  if(first_call) {
    /* TODO: I'm not totally sure what happens when the execution mode of jail
     * and the execution mode of the client process don't match on this first
     * exec.  For now we'll just assume nothing went wrong and the first result
     * is alwasy from exec. */
		if(true || st.get_syscall() == sys_execve) {
      first_call = false;
			pdata.enter_call = false;
      return FILTER_NO_ACTION;
		}

    log_error(pdata.pid, "first system call not execve");
    return FILTER_KILL_ALL;
  }
  safemem_reset(pdata);

  filter_action action;
  pdata.enter_call = !pdata.enter_call;
  if(pdata.enter_call) {
    action = filter_syscall_enter(pdata, st);
  } else {
    action = filter_syscall_exit(pdata, st);
  }

  return get_passive() ? FILTER_NO_ACTION : action;
}

std::list<filter*> create_root_filters() {
  std::list<filter*> filters;
  filters.push_back(new memory_filter());
  if(!get_files().empty()) {
    filters.push_back(new file_filter());
  }
  if(!get_exec_match().empty() || get_processes() != 0 || get_threads() != 0) {
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

void filter::on_exit(pid_data& pdata, exit_data& data) {
}

filter* filter::on_clone() {
  return ref();
}

filter* filter::on_fork() {
  return ref();
}

filter_action filter::filter_syscall_enter(pid_data& pdata, process_state& st) {
  return FILTER_NO_ACTION;
}

filter_action filter::filter_syscall_exit(pid_data& pdata, process_state& st) {
  return FILTER_NO_ACTION;
}

static unsigned long long query_wall_time_us() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec * 1000000LL + tv.tv_usec;
}

base_filter::base_filter() {
  start_wall_time = query_wall_time_us();
}

base_filter::~base_filter() {
}

void base_filter::on_exit(pid_data& pdata, exit_data& data) {
  data.wall_time_us = query_wall_time_us() - start_wall_time;
}

filter* base_filter::on_clone() {
  return ref();
}

filter* base_filter::on_fork() {
  return new base_filter();
}

filter_action base_filter::filter_syscall_enter(pid_data& pdata,
                                                process_state& st) {
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

    case sys_futex:
    case sys_nanosleep:
      break;

    default:
      return FILTER_NO_ACTION;
  }
  return FILTER_PERMIT_SYSCALL;
}
