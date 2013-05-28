#include <regex.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <sys/user.h>
#include <sys/ptrace.h>

#include "config.h"
#include "sjail.h"
#include "filter.h"
#include "memory.h"
#include "report.h"
#include "process_state.h"

#include <stdio.h>

static int regex_init = false;
static regex_t file_reg;

static bool is_file_allowed(pid_t pid, std::string file) {
  if(get_log_level() >= 4) {
    log_info(pid, 4, "open file " + file);
  }
  if(!regex_init) {
    if(regcomp(&file_reg, get_files().c_str(), REG_EXTENDED | REG_NOSUB)) {
      log_violation(pid, "failed to compile file regexp");
      return false;
    }
    regex_init = true;
  }
  return regexec(&file_reg, file.c_str(), (size_t)0, NULL, 0) == 0;
}

static bool filter_param_access(pid_data& pdata, process_state& st,
                                size_t idx, int mode, bool log) {
  pid_t pid = st.get_pid();
  char fullpath[PATH_MAX];

  char* file = (char*)safemem_read_pid_to_null(pdata, st.get_param(idx));
  if(!file) {
    if(log) log_violation(pid, "could not read path");
    return true;
  }

  char* ret = realpath(file, fullpath);
  if(ret != fullpath && get_rdonly()) {
    if(log) log_violation(pid, "could not find file " + std::string(file));
    return true;
  }

  if(!is_file_allowed(pid, std::string(fullpath))) {
    if(log) {
      log_violation(pid, "Attempt to access restricted file " +
                         std::string(file));
    }
    return true;
  }

  if(get_rdonly() && (mode & ~(F_OK | R_OK | X_OK))) {
    if(log) log_violation(pid, "write access denied");
    return true;
  }

  if(!get_passive()) {
    uintptr_t rem_addr = safemem_remote_addr(pdata, file);
    if(!rem_addr) {
      log_violation(pid, "cannot allow file op without safe mem installed");
      return true;
    }
    st.set_param(idx, rem_addr);
  }

  return false;
}

file_filter::file_filter() {
}

file_filter::~file_filter() {
}

filter_action file_filter::filter_syscall_enter(pid_data& pdata,
                                                process_state& st) {
  bool block = false;
  switch(st.get_syscall()) {
    case sys_access: {
      block = filter_param_access(pdata, st, 0, st.get_param(1), false);
    } break;

    case sys_stat:
    case sys_stat64: {
      block = filter_param_access(pdata, st, 0, R_OK, true);
    } break;
    case sys_fstat: 
    case sys_fstat64:
      break; /* Takes a file descriptor. */

    /* Standard polling functionality */
    case sys_poll:
    case sys_ppoll:
    case sys_select:
    case sys_pselect6:
    case sys_epoll_create:
    case sys_epoll_create1:
    case sys_epoll_ctl:
    case sys_epoll_wait:
    case sys_epoll_pwait:
      break;

    /* Probably too esoteric to be worth thinking about. */
    /* case sys_lstat: break; */

    case sys_open: {
      int flags = st.get_param(2) & O_ACCMODE;
      int mode = F_OK;
      if(flags == O_RDONLY || flags == O_RDWR) mode |= R_OK;
      if(flags == O_WRONLY || flags == O_RDWR) mode |= W_OK;
      block = filter_param_access(pdata, st, 0, mode, true);
    } break;

    case sys_dup:
    case sys_dup2:
    case sys_dup3:
      break;

    default:
      return FILTER_NO_ACTION;
  }
  return block ? FILTER_BLOCK_SYSCALL : FILTER_PERMIT_SYSCALL;
}
