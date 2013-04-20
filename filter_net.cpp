#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include <string>

#include <regex.h>

#include "config.h"
#include "filter.h"
#include "memory.h"
#include "report.h"
#include "process_state.h"

#define SOCKOP_socket 1
#define SOCKOP_bind 2
#define SOCKOP_connect 3
#define SOCKOP_listen 4
#define SOCKOP_accept 5
#define SOCKOP_getsockname 6
#define SOCKOP_getpeername 7
#define SOCKOP_socketpair 8
#define SOCKOP_send 9
#define SOCKOP_recv 10
#define SOCKOP_sendto 11
#define SOCKOP_recvfrom 12
#define SOCKOP_shutdown 13
#define SOCKOP_setsockopt 14
#define SOCKOP_getsockopt 15
#define SOCKOP_sendmsg 16
#define SOCKOP_recvmsg 17
#define SOCKOP_accept4 18
#define SOCKOP_recvmmsg 19
#define SOCKOP_sendmmsg 20

#define SOCK_TYPE_MASK 0xF

static int regex_init = false;
static regex_t net_reg;

static bool remote_client_allowed(pid_t pid, param_t* args) {
  param_t addr = args[0];
  param_t addr_sz = args[1];
  if(addr == 0) {
    return true;
  } else if(addr_sz < sizeof(sa_family_t)) {
    log_violation(pid, "address too small");
    return false;
  }

  char buf[INET6_ADDRSTRLEN];
  void* vaddr = safemem_read_pid(pid, addr, addr_sz);
  if(!vaddr) {
    log_violation(pid, "unreadable remote address family");
    return false;
  }

  std::string rem_addr;
  sa_family_t family = *(sa_family_t*)vaddr;
  switch(family) {
    case AF_INET:
    case AF_INET6: {
      switch(addr_sz) {
        case sizeof(sockaddr_in): {
          sockaddr_in* sin = (sockaddr_in*)vaddr;
          if(!inet_ntop(family, &sin->sin_addr, buf, sizeof(buf))) {
            log_violation(pid, "could not convert network "
                          "address to presentation form");
            return false;
          }
          rem_addr = std::string(buf) + ";" +
                        convert<std::string>(ntohs(sin->sin_port));
          break;
        } case sizeof(sockaddr_in6): {
          sockaddr_in6* sin = (sockaddr_in6*)vaddr;
          if(!inet_ntop(family, &sin->sin6_addr, buf, sizeof(buf))) {
            log_violation(pid, "could not convert network "
                          "address to presentation form");
            return false;
          }
          rem_addr = std::string(buf) + ";" +
                        convert<std::string>(ntohs(sin->sin6_port));
          break;
        } default: {  
          log_violation(pid, "unexpected remote address struct size");
          return false;
        }
      }
      rem_addr += family == AF_INET ? ";INET" : ";INET6";
      break;
    } case AF_UNIX: {
      if(sizeof(sockaddr_un) > addr_sz) {
        log_violation(pid, "unexpected remote address struct size");
        return false;
      }
      
      sockaddr_un* sin = (sockaddr_un*)vaddr;
      for(size_t i = 0; ; i++) {
        if(i == sizeof(sin->sun_path) || sin->sun_path[i] == ';') {
          log_violation(pid, "unix path malformed");
          return false;
        }
        if(!sin->sun_path[i]) {
          break;
        }
      }
      rem_addr = std::string(sin->sun_path) + ";0;UNIX";
      break;
    } default: {
      log_violation(pid, "unsupported remote address family");
      return false;
    }
  }

  if(!regex_init && !get_net_regexp().empty()) {
    if(regcomp(&net_reg, get_net_regexp().c_str(), REG_EXTENDED | REG_NOSUB)) {
      log_violation(pid, "failed to compile net regexp");
      return false;
    }
    regex_init = true;
  }

  if(!regex_init || regexec(&net_reg, rem_addr.c_str(), (size_t)0, NULL, 0)) {
    log_violation(pid, std::string("attempted to communicate with ") +
                       rem_addr);
    return false;
  }

  if(!get_passive()) {
    intptr_t rem_addr = safemem_remote_addr(pid, vaddr);
    if(!rem_addr) {
      log_violation(pid, "cannot allow net op without safe mem installed");
      return false;
    }
    args[0] = rem_addr;
  }

  log_info(pid, 1, "net address ok: " + rem_addr);
  return true;
}

net_filter::net_filter() {
}

net_filter::~net_filter() {
}

filter_action net_filter::filter_syscall_enter(process_state& st) {
  int op;
  bool generic_call = false;
  pid_t pid = st.get_pid();
  switch(st.get_syscall()) {
    case sys_socketcall:
      generic_call = true;
      op = st.get_param(0);
      break;

#define DOCASE(x) case sys_ ## x: op = SOCKOP_ ## x; break
    DOCASE(socket);
    DOCASE(bind);
    DOCASE(connect);
    DOCASE(listen);
    DOCASE(accept);
    DOCASE(getsockname);
    DOCASE(getpeername);
    DOCASE(socketpair);
    DOCASE(send);
    DOCASE(recv);
    DOCASE(sendto);
    DOCASE(recvfrom);
    DOCASE(shutdown);
    DOCASE(setsockopt);
    DOCASE(getsockopt);
    DOCASE(sendmsg);
    DOCASE(recvmsg);
    DOCASE(accept4);
    DOCASE(recvmmsg);
    DOCASE(sendmmsg);
#undef DOCASE

    default:
      return FILTER_NO_ACTION;
  }

  /* Quickly filter out always yes/no syscalls. */
  size_t nargs = 0;
  size_t addr_pos = 6;
  switch(op) {
    case SOCKOP_bind:
    case SOCKOP_listen:
    case SOCKOP_accept:
    case SOCKOP_accept4:
      return get_listen() ? FILTER_PERMIT_SYSCALL : FILTER_BLOCK_SYSCALL;

    case SOCKOP_getsockname:
    case SOCKOP_getpeername:
    case SOCKOP_shutdown: 
      return FILTER_PERMIT_SYSCALL;

    /* Need to vet the remote address by peering into msg to support this. */
    case SOCKOP_sendmsg:
    case SOCKOP_recvmsg:
    case SOCKOP_sendmmsg:
    case SOCKOP_recvmmsg:
      return FILTER_BLOCK_SYSCALL;

    /* We probably can support some options by I'm not comfortable white listing
     * this method entirely. */
    case SOCKOP_setsockopt:
      return FILTER_BLOCK_SYSCALL;

    case SOCKOP_getsockopt:
      return FILTER_PERMIT_SYSCALL;

    /* We only vet the remote address.  To use these you must have already
     * successfully set one up. */
    case SOCKOP_send:
    case SOCKOP_recv:
    case SOCKOP_recvfrom:
      return FILTER_PERMIT_SYSCALL;
      
    /* We need to load and sanitize the arguments before we vet. */
    case SOCKOP_socket: nargs = 3; break;
    case SOCKOP_socketpair: nargs = 4; break;
    case SOCKOP_connect: nargs = 3; addr_pos = 1; break;
    case SOCKOP_sendto: nargs = 6; addr_pos = 4; break;

    default:
      log_violation(pid, "unknown socket operation");
      return FILTER_BLOCK_SYSCALL;
  }

  /* Read in parameters wherever they come from. */
  void* params = NULL;
  param_t s_params[6];
  if(generic_call) {
    size_t width = st.word_width();
    params = safemem_read_pid(pid, st.get_param(1), nargs * width);
    if(!params) {
      log_violation(pid, "could not read socketcall parameters");
      return FILTER_BLOCK_SYSCALL;
    }

    for(size_t i = 0; i < nargs; i++) {
      s_params[i] = st.read_uword((char*)params + i * width);
    }
  } else {
    for(size_t i = 0; i < nargs; i++) {
      s_params[i] = st.get_param(i);
    }
  }

  if(addr_pos < nargs &&
     !remote_client_allowed(pid, s_params + addr_pos)) {
    return FILTER_BLOCK_SYSCALL;
  }

  switch(op) {
    case SOCKOP_socket:
    case SOCKOP_socketpair: {
      if(s_params[0] != PF_INET && s_params[0] != PF_INET6 &&
         s_params[0] != PF_UNIX) {
        log_violation(pid, "unsupported socket domain used");
        return FILTER_BLOCK_SYSCALL;
      }
      param_t sock_type = s_params[1];
#ifdef SOCK_TYPE_MASK
      sock_type &= SOCK_TYPE_MASK;
#endif
      if(sock_type != SOCK_STREAM && sock_type != SOCK_DGRAM) {
        log_violation(pid, "protocol other than tcp or udp used");
        return FILTER_BLOCK_SYSCALL;
      }
      if(s_params[1] == SOCK_STREAM && !get_tcp()) {
        log_violation(pid, "tcp used");
        return FILTER_BLOCK_SYSCALL;
      }
      if(s_params[1] == SOCK_DGRAM && !get_udp()) {
        log_violation(pid, "udp used");
        return FILTER_BLOCK_SYSCALL;
      }
    } break;

    /* Their parameters are vetted earlier. */
    case SOCKOP_connect:
    case SOCKOP_sendto:
      break;

    default:
      log_violation(pid, "internal error");
      return FILTER_BLOCK_SYSCALL;
  }

  /* If socketcall was used the parameters are held in the client address space
   * and we need to move them to a safe location. */
  if(generic_call && !get_passive()) {
    size_t width = st.word_width();
    for(size_t i = 0; i < nargs; i++) {
      st.write_uword((char*)params + i * width, s_params[i]);
    }

    intptr_t rem_addr = safemem_remote_addr(pid, params);
    if(!rem_addr) {
      log_violation(pid, "cannot allow socketcall without safe mem installed");
      return FILTER_BLOCK_SYSCALL;
    }
    st.set_param(1, rem_addr);
  }
  return FILTER_PERMIT_SYSCALL;
}
