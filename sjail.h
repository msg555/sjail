#ifndef JAIL_JAIL_H
#define JAIL_JAIL_H

#include <list>
#include <stdint.h>

struct rusage;

static const size_t MAX_PIDS = 1 << 16;

class filter;
class process_state;

struct pid_data {
  pid_data() : pid(-1) {
  }

  pid_data(pid_t pid, bool enter_call, uintptr_t safe_mem_base,
           std::list<filter*>&& filters)
      : pid(pid), enter_call(enter_call), installing_safe_mem(false),
        safe_mem_base(safe_mem_base), restore_state(nullptr), filters(filters) {
  }

  pid_t pid;
  bool enter_call;
  bool installing_safe_mem;
  uintptr_t safe_mem_base;
  process_state* restore_state;
  std::list<std::pair<char*, size_t> > allocations;
  std::list<filter*> filters;
};

enum exit_type {
  EXIT_STATUS,
  EXIT_SIGNAL,
  EXIT_KILLED
};

struct exit_data {
  exit_data(exit_type type, rusage* resources) :
      type(type), signum(0), status(0), resources(resources),
      max_mapped_bytes(0) {
  }

  enum exit_type type;
  int signum;
  int status;

  rusage* resources;
  unsigned long max_mapped_bytes;
  unsigned long long wall_time_us;
};

enum filter_action {
  FILTER_NO_ACTION,
  FILTER_KILL_PID,
  FILTER_KILL_ALL,
  FILTER_BLOCK_SYSCALL,
  FILTER_PERMIT_SYSCALL,
  FILTER_CHANGED_SYSCALL
};

#endif // JAIL_JAIL_H
