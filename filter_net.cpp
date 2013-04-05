#if 0
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
#include <linux/netlink.h>
#include <sys/syscall.h>

#include "config.h"
#include "filter.h"
#include "syscall_tab.h"
#include "signal_tab.h"
#include "report.h"
#include "memory.h"

#ifdef SYS_socketcall
#define SYS_socket SYS_SOCKET
#define SYS_socketpair SYS_SOCKETPAIR
#define SYS_connect SYS_CONNECT
#define SYS_bind SYS_BIND
#define SYS_listen SYS_LISTEN
#define SYS_accept SYS_ACCEPT
#define SYS_getsockname SYS_GETSOCKNAME
#define SYS_getpeername SYS_GETPEERNAME
#define SYS_sendto SYS_SENDTO
#define SYS_sendmsg SYS_SENDMSG
#define SYS_recvfrom SYS_RECVFROM
#define SYS_recvmsg SYS_RECVMSG
#define SYS_shutdown SYS_SHUTDOWN
#define SYS_getsockopt SYS_GETSOCKOPT
#define SYS_setsockopt SYS_SETSOCKOPT
#endif

map<int, unsigned long> sock_map;

bool read_from_pid_compat(pid_t pid, char* dst,
                          intptr_t remote_addr, size_t len) {
  void* addr = read_from_pid(pid, remote_addr, len);
  if(!addr) {
    return false;
  }
  memcpy(dst, addr, len);
  return true;
}

bool remote_client_allowed(pid_t pid, unsigned long addr, unsigned long addr_sz,
                           const string& log_prefix) {
  string rem_addr;
  char buf[INET6_ADDRSTRLEN];
  sa_family_t family;

  if(!read_from_pid_compat(pid, (char *)&family, addr, sizeof(family))) {
    log_violation(pid, "unreadable remote address family");
    return false;
  }
  switch(family) {
    case AF_INET:
    case AF_INET6: {
      switch(addr_sz) {
        case sizeof(sockaddr_in): {
          sockaddr_in sin;
          if(!read_from_pid_compat(pid, (char *)&sin, addr, sizeof(sin))) {
            log_violation(pid, "unreadable remote address struct");
            return false;
          }
          if(!inet_ntop(family, &sin.sin_addr, buf, sizeof(buf))) {
            log_violation(pid, "could not convert network "
                          "address to presentation form");
            return false;
          }
          rem_addr = string(buf) + ";" + convert<string>(ntohs(sin.sin_port));
          break;
        } case sizeof(sockaddr_in6): {
          sockaddr_in6 sin;
          if(!read_from_pid_compat(pid, (char *)&sin, addr, sizeof(sin))) {
            log_violation(pid, "unreadable remote address struct");
            return false;
          }
          inet_ntop(family, &sin.sin6_addr, buf, sizeof(buf));
          rem_addr = string(buf) + ";" + convert<string>(ntohs(sin.sin6_port));
          break;
        } default: {  
          log_violation(pid, "unexpected remote address structk size");
          return false;
        }
      }
      rem_addr += family == AF_INET ? ";INET" : ";INET6";
      break;
    } case AF_UNIX: {
      sockaddr_un sin;
      if(sizeof(sin) > addr_sz) {
        log_violation(pid, "unexpected remote address struct size");
        return false;
      }
      if(!read_from_pid_compat(pid, (char *)&sin, addr, sizeof(sin))) {
        log_violation(pid, "unreadable remote address struct");
        return false;
      }
      rem_addr = string(sin.sun_path) + ";0;UNIX";
      break;
    } default: {
      log_violation(pid, "unsupported remote address struct family " +
                    convert<string>(family));
      return false;
    }
  }

  if(!get_net_regexp().empty()) {
    regex_t re;
    if(regcomp(&re, get_net_regexp().c_str(), REG_EXTENDED | REG_NOSUB)) {
      log_violation(pid, "failed to compile net regexp");
      return false;
    }
    int status = regexec(&re, rem_addr.c_str(), (size_t)0, NULL, 0);
    regfree(&re);
    if(status) {
      log_violation(pid, string("attempted to communicate with ") + rem_addr);
      return false;
    }
  }

  log_info(pid, 1, log_prefix + rem_addr);
  return true;
}

bool process_network_call(pid_t pid, int call_num,
                          unsigned long socket_param[6]) {
  if(!get_net()) {
    log_violation(pid, "socket call");
    return false;
  }
  switch(call_num) {
    case SYS_socket:
    case SYS_socketpair:
      #ifdef SYS_socketcall
      if(!read_from_pid_compat(pid, (char *)socket_param, socket_param[1],
                        sizeof(unsigned long) * 3)) {
        log_violation(pid, "unreadable parameters to socket/socketpair");
        return false;
      }
      #endif
      if(socket_param[0] != PF_INET && socket_param[0] != PF_INET6 &&
        socket_param[0] != PF_LOCAL) {
        log_violation(pid, "unsupported domain used " +
                      convert<string>(socket_param[0]));
        return false;
      }
      if(socket_param[1] != SOCK_STREAM && socket_param[1] != SOCK_DGRAM) {
        log_violation(pid, "protocol other than tcp or udp used");
        return false;
      }
      if(socket_param[1] == SOCK_STREAM && !get_tcp()) {
        log_violation(pid, "tcp used");
        return false;
      }
      if(socket_param[1] == SOCK_DGRAM && !get_udp()) {
        log_violation(pid, "udp used");
        return false;
      }
      break;
        
    case SYS_connect: {
      #ifdef SYS_socketcall
      if(!read_from_pid_compat(pid, (char *)socket_param,
                        socket_param[1], sizeof(unsigned long) * 3)) {
        log_violation(pid, "unreadable parameters to connect");
        return false;
      }
      #endif
      if(!remote_client_allowed(pid, socket_param[1], socket_param[2],
                                "socket connect to ")) {
        return false; /* The violation is logged by remote_client_allowed. */
      }
      break;
    }

    case SYS_bind:
    case SYS_listen:
    case SYS_accept:
      if(!get_listen()) {            
        log_violation(pid, "attempted to bind/listen/accept");
        return false;
      }
      break;

    #ifdef SYS_socketcall
    case SYS_SEND:
    case SYS_RECV:
      break;
    #endif

    case SYS_sendto:
      if(!get_tcp() || get_udp() && sock_map[socket_param[0]] == SOCK_DGRAM) {
        // We need to verify the remote address.
        #ifdef SYS_socketcall
        if(!read_from_pid_compat(pid, (char *)socket_param, socket_param[1],
                          sizeof(unsigned long) * 6)) {
          log_violation(pid, "unreadable parameters to sendto");
          return false;
        }
        #endif
        if(!remote_client_allowed(pid, socket_param[4], socket_param[5],
                                  "socket send to ")) {
          return false; /* The violation is logged by remote_client_allowed. */
        }
      }
      break;
    case SYS_recvfrom:
      if(!get_tcp() || get_udp() && sock_map[socket_param[0]] == SOCK_DGRAM) {
        /* We need to verify the remote address. */
        #ifdef SYS_socketcall
        if(!read_from_pid_compat(pid, (char *)socket_param, socket_param[1],
                          sizeof(unsigned long) * 6)) {
          log_violation(pid, "unreadable parameters to recvfrom");
          return false;
        }
        #endif
        if(!remote_client_allowed(pid, socket_param[4], socket_param[5],
                                  "socket recv from ")) {
          return false; /* The violation is logged by remote_client_allowed. */
        }
      }
      break;

    case SYS_getsockname:
    case SYS_getpeername:
    case SYS_sendmsg:
    case SYS_recvmsg:
    case SYS_shutdown: 
    case SYS_getsockopt:
      break;

    case SYS_setsockopt:
      // There are some options that shouldn't be allowed.  There are lots
      // of options available to be changed and it's difficult to discern
      // which ones are and aren't ok so I've disabled them all.
      log_violation(pid, "setsockopt used");

    default:
      log_violation(pid, "unknown socket call made");
      return false;
  }
  return true;
}


void process_network_exit(pid_t pid, int call_num, unsigned long result,
                          unsigned long socket_param[6]) {
  // TODO(msg): get this working correctly.  Fails to read parameters?
  return;
  switch(call_num) {
    case SYS_socket:
      #ifdef SYS_socketcall
      if(read_from_pid_compat(pid, (char *)socket_param, socket_param[1],
                       sizeof(unsigned long) * 2)) {
        log_info(pid, 2, "failed to read socket parameters on exit");
        return;
      }
      #endif
      if(result != -1) {
        sock_map[result] = socket_param[1];
      }
      break;
    case SYS_socketpair:
      #ifdef SYS_socketcall
      if(read_from_pid_compat(pid, (char *)socket_param, socket_param[1],
                       sizeof(unsigned long) * 3)) {
        log_info(pid, 2, "failed to read socketpair parameters on exit");
        return;
      }
      #endif
      if(result != -1) {
        sock_map[result] = socket_param[1];
        // TODO(msg): make sure this is how this really works...
        if(result != -1) {
          int ss[2];
          read_from_pid_compat(pid, (char *)ss, socket_param[3], sizeof(ss));
          sock_map[ss[0]] = sock_map[ss[1]] = socket_param[1];
        }
      }
      break;
  }
}

#endif
