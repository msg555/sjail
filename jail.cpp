#include <iostream>
#include <cstdlib>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <pwd.h>
#include <stdio.h>

#include "report.h"
#include "config.h"
#include "signal_tab.h"
#include "filterer.h"

using namespace std;

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

int main(int argc, char ** argv) {
    int res = parse_arguments(argc, argv);
    if(res == -1 || res == argc) {
        print_usage();
        return -1;
    }
    parse_file(get_conf_file().c_str());
    parse_arguments(argc, argv); // Sort of silly but command line arguments override.
    if(get_help()) {
        print_usage();
        return 0;
    }

    int pid = fork();
    if(pid == -1) {
        cerr << "Fork failed" << endl;
        return 1;
    } else if(pid == 0) {
        // Do we want to close stderr or stdout?
        // Do we want to change to a different user (say nobody)?
        // Do we want to set some resource limits here?

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
        if(get_mem() != MEM_NO_LIMIT) {
          setlimit(RLIMIT_AS, get_mem());
        }
        if(pw_group) {
          if(setgid(pw_group->pw_uid) || setegid(pw_group->pw_uid)) {
            return syscall_failed("Failed to set group id");
          }
        }
        if(pw_user) {
          if(setuid(pw_user->pw_uid) || seteuid(pw_user->pw_uid)) {
            return syscall_failed("Failed to set user id");
          }
        }

        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(argv[res], argv + res);
        return syscall_failed("execvp");
    }

    if(!init_report()) {
      cerr << "Failed to open report file" << endl;
      kill(pid, SIGKILL);
      return 1;
    }

    while(1) {
        int status;
        rusage resources;
        if(wait4(pid, &status, WUNTRACED, &resources) == -1) {
            cerr << "wait4 failed :'(" << endl;
            kill(pid, SIGKILL);
            return 1;
        }

        if(WIFSIGNALED(status)) {
            //WIFSIGNALED(status)
            //       returns true if the child process was terminated by a signal.
            //WTERMSIG(status)
            //       returns the number of the signal that caused the child process to
            //       terminate.  This macro should only be employed if WIFSIGNALED
            //       returned true.
            DEBUG("Child terminated with signal " << get_signal_name(WTERMSIG(status)));
            log_term_signal(WTERMSIG(status));
            return 0;
        } else if(WIFEXITED(status)) {
            //WIFEXITED(status)
            //       returns true if the child terminated normally, that is, by
            //       calling exit(3) or _exit(2), or by returning from main().
            //WEXITSTATUS(status)
            //       returns the exit status of the child.  This consists of the least
            //       significant 8 bits of the status argument that the child
            //       specified in a call to exit(3) or _exit(2) or as  the  argument
            //       for a return statement in main().  This macro should only be
            //       employed if WIFEXITED returned true.
            DEBUG("Child process exited with status " << WEXITSTATUS(status));
            log_exit_status(WEXITSTATUS(status));
            return 0;
        } else if(WIFSTOPPED(status)) {
            //WIFSTOPPED(status)
            //       returns true if the child process was stopped by delivery of a
            //       signal; this is only possible if the call was done using
            //       WUNTRACED or when the child is being traced (see ptrace(2)).
            int sig = WSTOPSIG(status);

            if(sig == SIGTRAP) {
                // This is where we intercept system calls.
                try {
                  process_system_call(pid);
                } catch(std::bad_alloc) {
                  log_error("out of state space");
                  kill(pid, SIGKILL);
                  return 1;
                }
            } else if(sig == SIGSEGV) {
                kill(pid, SIGKILL);
                return 0;
            } else {
                DEBUG("Child was stopped by signal " << get_signal_name(sig));
            }

            errno = 0;
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            if(errno) {
                cerr << "ptrace resume failed" << endl;
                kill(pid, SIGKILL);
                return 1;
            }
        } else if(WIFCONTINUED(status)) {
            //WIFCONTINUED(status)
            //       (since Linux 2.6.10) returns true if the child process was
            //       resumed by delivery of SIGCONT.
            DEBUG("Child was allowed to continue");
        } else {
            cerr << "Unknown status returned by wait4" << endl;
        }
    }

    return 1;
}


