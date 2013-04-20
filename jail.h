#ifndef JAIL_JAIL_H
#define JAIL_JAIL_H

#include <list>
#include <stdint.h>

static const size_t MAX_PIDS = 1 << 16;

class filter;
class process_state;

typedef struct pid_data {
  bool tracing_proc;
  bool enter_call;

  bool installing_safe_mem;
  uintptr_t safe_mem_base;
  process_state* restore_state;
  std::list<filter*> filters;
} pid_data;

typedef enum filter_action {
  FILTER_NO_ACTION,
  FILTER_KILL_PID,
  FILTER_KILL_ALL,
  FILTER_BLOCK_SYSCALL,
  FILTER_PERMIT_SYSCALL,
  FILTER_CHANGED_SYSCALL
} filter_action;

extern pid_data proc[MAX_PIDS];

#endif // JAIL_JAIL_H
