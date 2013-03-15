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

#include "config.h"
#include "filterer.h"
#include "syscall_tab.h"
#include "signal_tab.h"
#include "report.h"

using namespace std;

static long call_num = 0;
static bool first_call = true;
static bool enter_call = true;
static bool call_denied = false;

bool read_from_pid(char * dst_addr, unsigned long remote_src_addr, long len, int pid) {
  for(int i = 0; i < len; ) {
    int a = remote_src_addr + i & sizeof(long) - 1;
    int b = min((long)sizeof(long), a + len - i);
    errno = 0;
    long v = ptrace(PTRACE_PEEKDATA, pid, remote_src_addr + i & ~(sizeof(long) - 1), NULL);
    if(errno == EFAULT) {
      return false;
    }
    memcpy(dst_addr + i, (char *)&v + a, b - a);
    i += b - a;
  }
  return true;
}

bool read_from_pid_to_null(char * dst_addr, unsigned long remote_src_addr, long max_len, int pid) {
  // It may write a few extra bytes after the null.
  for(int i = 0; i < max_len; ) { 
    int a = remote_src_addr + i & sizeof(long) - 1;
    int b = min((long)sizeof(long), a + max_len - i);
    errno = 0;
    long v = ptrace(PTRACE_PEEKDATA, pid, remote_src_addr + i & ~(sizeof(long) - 1), NULL);
    if(errno == EFAULT) {
      return false;
    }
    memcpy(dst_addr + i, (char *)&v + a, b - a);

    // Look for a null so we can stop.
    for(int j = 0; j < b - a; j++) {
      if(!dst_addr[i + j]) {
        return true;
      }
    }

    i += b - a;
  }
  dst_addr[max_len - 1] = 0;
  return false;
}


void process_system_call(int pid) {
  user_regs_struct reg;
  if(ptrace(PTRACE_GETREGS, pid, NULL, &reg) < 0) {
    cerr << "ptrace_getregs failed unexpectedly" << endl;
    kill(pid, SIGKILL);
    exit(1);
  }
	call_num++;

  enter_call = !enter_call;
  unsigned long state;

  #ifdef __x86_64__
  unsigned long long & sys_num = reg.orig_rax;
  unsigned long long & result = reg.rax;
  unsigned long long & param1 = reg.rdi;
  unsigned long long & param2 = reg.rsi;
  unsigned long long & param3 = reg.rdx;
  unsigned long long & param4 = reg.rcx;
  unsigned long long & param5 = reg.r8;
  unsigned long long & param6 = reg.r9;
  #endif
  #ifdef __i386__
  long & sys_num = reg.orig_eax;
  long & result = reg.eax;
  long & param1 = reg.ebx;
  long & param2 = reg.ecx;
  long & param3 = reg.edx;
  long & param4 = reg.esi;
  long & param5 = reg.edi;
  long & param6 = reg.ebp;
  #endif

  if(first_call) {
		if(sys_num == SYS_execve) {
			if(call_num > 2) {
				log_violation("illegal execve may have been called... terminating");
    		kill(pid, SIGKILL);
    		exit(1);
			}
			enter_call = false;
		} else if(call_num == 1) {
      cerr << "First system call not execve" << endl;
      if(!get_passive()) {
        kill(pid, SIGKILL);
        exit(0);
      }
    } else {
			first_call = false;
		}
    return;
  }

  if(call_denied) {
    call_denied = false;
    result = -1;
    if(!get_passive())
      ptrace(PTRACE_SETREGS, pid, NULL, &reg);
    return;
  }

  unsigned long socket_param[6] = {param1, param2, param3, param4, param5, param6};

  if(!enter_call) {
    switch(sys_num) {
    // TODO(msg): fix this.
    /*
      case SYS_dup:
        if(result != -1 && get_udp()) {
          typeof(sock_map.begin()) it = sock_map.find(param1);
          if(it != sock_map.end()) {
            sock_map[result] = it->second;
          }
        }
        break;

      case SYS_dup2:
        if(result != -1 && get_udp()) {
          typeof(sock_map.begin()) it = sock_map.find(param1);
          if(it != sock_map.end()) {
            sock_map[result] = it->second;
          } else {
            sock_map.erase(result);
          }
        }
        break;
*/
      // Networking syscalls.
      #ifdef SYS_socketcall    
      case SYS_socketcall:
        process_network_exit(param1, result, socket_param, pid);
        break;
      #else
      case SYS_socket:
      case SYS_socketpair:
      case SYS_connect:
      case SYS_bind:
      case SYS_listen:
      case SYS_accept:
      case SYS_sendto:
      case SYS_recvfrom:
      case SYS_getsockname:
      case SYS_getpeername:
      case SYS_sendmsg:
      case SYS_recvmsg:
      case SYS_shutdown: 
      case SYS_getsockopt:
      case SYS_setsockopt:
        process_network_exit(sys_num, result, socket_param, pid);
        break;
      #endif
    }
    return;
  }

  // System calls are frequent so let's proactively avoid the cost of the string
  // manipulation required here and the function call if it is not requested.
  if(get_report() && get_log_level() >= 5) {
    log_info(5, string("syscall ") + get_syscall_name(sys_num));
  }

  switch(sys_num) {
    #ifdef __x86_64__
    case SYS_arch_prctl:
		case SYS_pread64:
		case SYS_pwrite64:
      break;
    #endif
    #ifdef __i386__
    case SYS_fstat64:
    case SYS_fcntl64:
    case SYS_stat64:
    case SYS_lstat64:
    case SYS_getuid32:
    case SYS_geteuid32:
    case SYS_getgid32:
    case SYS_getegid32:
    case SYS_setresuid32: // TODO: evaluate...
    case SYS_setresgid32: // TODO: evaluate...
    case SYS_setuid32: // TODO: evaluate...
    case SYS_setgid32: // TODO: evaluate...
    case SYS_sigaction:
    case SYS_mmap2:
    case SYS__llseek:
    case SYS_ugetrlimit:
      break;
    #endif

    case SYS_open:
        if(!process_fileopen(param1, param2, pid))
            goto Default;
        break;

    case SYS_read:
    case SYS_readv:
        break;

    case SYS_write:
    case SYS_writev:
      break;    

    case SYS_dup:
    case SYS_dup2:
      break;

    case SYS_close:
      // TODO(msg): fix this
      /*
      if(get_net()) {
        sock_map.erase(param1);
      }
      */
      break;

    case SYS_fstat:
    case SYS_fcntl:
    case SYS_getuid:
    case SYS_geteuid:
    case SYS_getgid:
    case SYS_getegid:
    case SYS_access:
    case SYS_munmap:
    case SYS_uname:
    case SYS_exit:
    case SYS_exit_group:
    case SYS_rt_sigaction:
    case SYS_ioctl:
    case SYS_times:
    case SYS_mprotect:
    case SYS_getpid:
    case SYS_time:
    case SYS_set_tid_address: // TODO: evaluate...
    case SYS_setresuid: // TODO: evaluate...
    case SYS_setresgid: // TODO: evaluate...
    case SYS_setuid: // TODO: evaluate...
    case SYS_setgid: // TODO: evaluate...
    case SYS_umask: // TODO: evaluate...
    case SYS_poll: // TODO: evaluate...
    case SYS_nanosleep:
      break;

    case SYS_stat:
    case SYS_lstat:
    case SYS_gettimeofday:
    case SYS_futex:
    case SYS_sched_getparam:
    case SYS_sched_getscheduler:
      break;

    case SYS_brk:
    case SYS_mmap:
      break;

    case SYS_get_thread_area:
    case SYS_set_thread_area:
      break;

    case SYS_getrlimit:
      break;

    case SYS_kill:
      // You can't send a signal to anyone else.
      if(param1 != pid) {
        log_violation("attempted to send " + get_signal_name(param2) + " to process " + convert<string>(param1));
        goto Default;
      }
      break;

    case SYS_rt_sigprocmask:
      // Don't allow the child to block signals.
      if(param1 != SIG_UNBLOCK) {
        log_violation("attempted to block signals");
        goto Default;
      }
      break;

    // Networking syscalls.
    #ifdef SYS_socketcall    
    case SYS_socketcall:
      if(!process_network_call(param1, socket_param, pid))
        goto Default;
      break;
    #else
    case SYS_socket:
    case SYS_socketpair:
    case SYS_connect:
    case SYS_bind:
    case SYS_listen:
    case SYS_accept:
    case SYS_sendto:
    case SYS_recvfrom:
    case SYS_getsockname:
    case SYS_getpeername:
    case SYS_sendmsg:
    case SYS_recvmsg:
    case SYS_shutdown: 
    case SYS_getsockopt:
    case SYS_setsockopt:
      if(!process_network_call(sys_num, socket_param, pid))
        goto Default;
      break;
    #endif

    default:
    log_blocked_syscall(sys_num, result, param1, param2,
                        param3, param4, param5, param6);
    Default:
      if(enter_call) {
        // Make an invalid syscall to set errno to EINVAL.
        call_denied = true;
        sys_num = SYS_kill;
        param1 = pid;
        param2 = -1;
      }
      if(!get_passive())
        ptrace(PTRACE_SETREGS, pid, NULL, &reg);
      break;
  }
}

