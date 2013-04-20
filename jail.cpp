#include <iostream>
#include <cstdlib>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>

#include "jail.h"
#include "report.h"
#include "config.h"
#include "signal_tab.h"
#include "filter.h"
#include "memory.h"
#include "process_state.h"

using namespace std;

pid_data proc[MAX_PIDS];

int syscall_failed(const char* msg) {
  perror(msg);
  return 1;
}

void setlimit(int res, int hardlimit) {
  struct rlimit rl;
  rl.rlim_cur = rl.rlim_max = hardlimit;
  if(setrlimit(res, &rl)) {
    exit(syscall_failed("setrlimit"));
  }
}

int teardown_processes(const char* msg) {
  if(msg) {
    fprintf(stderr, "%s\n", msg);
  }
  for(int i = 0; i < MAX_PIDS; i++) {
    if(proc[i].tracing_proc) {
      ptrace(PTRACE_KILL, i, NULL, NULL);
    }
  }
  return 1;
}

bool cleanup_process(pid_t pid, size_t& trace_count) {
  proc[pid].tracing_proc = false;
  proc[pid].enter_call = false;
  for(; !proc[pid].filters.empty(); ) {
    filter* fltr = *proc[pid].filters.begin();
    proc[pid].filters.erase(proc[pid].filters.begin());

    if(fltr->unref()) {
      fltr->on_exit(pid);
      delete fltr;
    }
  }
  return --trace_count == 0;
}

int main(int argc, char ** argv) {
  int res = parse_arguments(argc, argv);
  if(res == -1 || res == argc) {
    print_usage(argv[0]);
    return -1;
  }

  if(!get_no_conf()) {
    parse_file(get_conf_file().c_str());
  }
  parse_arguments(argc, argv);
  if(get_help()) {
    print_usage(argv[0]);
    return 0;
  }

  init_process_state();
  if(!safemem_init()) {
    return syscall_failed("failed to init memory");
  }

  int pid_root = fork();
  if(pid_root == -1) {
    cerr << "Fork failed" << endl;
    return 1;
  } else if(pid_root == 0) {
    if(!safemem_map_unwritable()) {
      return syscall_failed("failed to map memory");
    }

#ifdef PATH_MAX
    char chroot_path[PATH_MAX];
#else
    char chroot_path[4096];
#endif
    if(!get_chroot().empty()) {
      if(chroot_path != realpath(get_chroot().c_str(), chroot_path)) {
        return syscall_failed("Failed to find real path of chroot");
      }
    }
    if(!get_cwd().empty()) {
      if(chdir(get_cwd().c_str())) {
        return syscall_failed("Failed to change working directory");
      }
    }
    if(!get_chroot().empty()) {
      if(chroot(chroot_path)) {
        return syscall_failed("Failed to change root directory");
      }
    }
    if(get_time() != TIME_NO_LIMIT) {
      setlimit(RLIMIT_CPU, get_time());
    }

    struct passwd* pw_user = NULL;
    struct passwd* pw_group = NULL;
    if(!get_group().empty()) {
      pw_group = getpwnam(get_group().c_str());
      if(!pw_group) {
        return syscall_failed("Failed to look up group id");
      }
    }
    if(!get_user().empty()) {
      pw_user = getpwnam(get_user().c_str());
      if(!pw_user) {
        return syscall_failed("Failed to look up user id");
      }
    }

    if(pw_group) {
      if(setresgid(pw_group->pw_uid, pw_group->pw_uid, pw_group->pw_uid)) {
        return syscall_failed("Failed to set group id");
      }
    }
    if(pw_user) {
      if(setresuid(pw_user->pw_uid, pw_user->pw_uid, pw_user->pw_uid)) {
        return syscall_failed("Failed to set user id");
      }
    }

    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    execvp(argv[res], argv + res);
    return syscall_failed("execvp");
  }

  proc[pid_root].tracing_proc = true;
  proc[pid_root].enter_call = true;
  proc[pid_root].filters = create_root_filters();

  if(!init_report()) {
    cerr << "Failed to open report file" << endl;
    return teardown_processes(NULL);
  }

  int fork_count = 0;
  int clone_count = 0;
  bool firstTrace = true;
  size_t trace_count = 1;
  for(;;) {
    pid_t pid;
    int status;
    rusage resources;
    pid = wait3(&status, WUNTRACED, &resources);
    if(pid == -1) {
      syscall_failed("wait4");
      return teardown_processes(NULL);
    }
    if(pid < 0 || MAX_PIDS <= pid) {
      return teardown_processes("unexpected pid from wait");
    }
    if(firstTrace) {
      ptrace(PTRACE_SETOPTIONS, pid, NULL,
             PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE);
      firstTrace = false;
    }

    if(WIFSIGNALED(status)) {
      log_term_signal(pid, WTERMSIG(status));
      if(cleanup_process(pid, trace_count)) {
        return 0;
      }
    } else if(WIFEXITED(status)) {
      log_exit_status(pid, WEXITSTATUS(status));
      if(cleanup_process(pid, trace_count)) {
        return 0;
      }
    } else if(WIFSTOPPED(status)) {
      int sig = WSTOPSIG(status);
      if(sig == SIGTRAP) {
        if((status >> 16 & 0xFFFF) == PTRACE_EVENT_FORK ||
           (status >> 16 & 0xFFFF) == PTRACE_EVENT_VFORK ||
           (status >> 16 & 0xFFFF) == PTRACE_EVENT_CLONE) {
          pid_t child_pid = -1;
          if(ptrace(PTRACE_GETEVENTMSG, pid, 0, &child_pid) == -1) {
            syscall_failed("ptrace(GETEVENTMSG)");
            return teardown_processes(NULL);
          } else if(child_pid < 0 || MAX_PIDS <= child_pid) {
            return teardown_processes("unexpected child pid from ptrace");
          } else if(proc[child_pid].tracing_proc) {
            return teardown_processes("already tracing child");
          }
          if((status >> 16 & 0xFFFF) == PTRACE_EVENT_CLONE) {
            ++clone_count;
            if(get_threads() >= 0 && clone_count > get_threads()) {
              log_violation(pid, "global thread count too high");
              if(kill(child_pid, SIGKILL)) {
                syscall_failed("kill");
                teardown_processes(NULL);
                return 1;
              }
              child_pid = -1;
            } else {
              proc[child_pid].filters = clone_filters(proc[pid].filters);
            }
          } else {
            ++fork_count;
            if(get_processes() >= 0 && fork_count > get_processes()) {
              log_violation(pid, "global process count too high");
              if(kill(child_pid, SIGKILL)) {
                syscall_failed("kill");
                return teardown_processes(NULL);
              }
              child_pid = -1;
            } else {
              proc[child_pid].filters = fork_filters(proc[pid].filters);
            }
          }
          if(child_pid != -1) {
            proc[child_pid].tracing_proc = true;
            proc[child_pid].safe_mem_base = proc[pid].safe_mem_base;
            trace_count++;
          }
        } else try {
          switch(filter_system_call(pid)) {
            case FILTER_KILL_PID:
              if(kill(pid, SIGKILL)) {
                syscall_failed("kill");
                return teardown_processes(NULL);
              } else if(cleanup_process(pid, trace_count)) {
                return 0;
              }
              break;
            case FILTER_KILL_ALL:
              return teardown_processes(NULL);
              break;
            default:
              errno = 0;
              ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
              break;
          }
        } catch(std::bad_alloc) {
          log_error(pid, "out of state space");
          return teardown_processes("out of memory");
        }
      } else {
        errno = 0;
        ptrace(PTRACE_CONT, pid, NULL, (void*)(intptr_t)sig);
        log_info(pid, 2, "signal " + get_signal_name(sig) + " delivered");
      }

      if(errno) {
        cerr << "ptrace resume failed" << endl;
        kill(pid, SIGKILL);
        return 1;
      }
    } else if(WIFCONTINUED(status)) {
      DEBUG("Child was allowed to continue");
    } else {
      cerr << "Unknown status returned by wait4" << endl;
    }
  }

  return 1;
}


