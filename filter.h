#ifndef JAIL_FILTER_H
#define JAIL_FILTER_H

#include <list>
#include <sys/types.h>

#include "jail.h"

class filter;
class process_state;

filter_action filter_system_call(pid_t pid);

std::list<filter*> create_root_filters();

std::list<filter*> clone_filters(const std::list<filter*>& filters);
std::list<filter*> fork_filters(const std::list<filter*>& filters);

class filter {
 public:
  filter();
  virtual ~filter();

  filter* ref();
  bool unref();
  
  virtual filter* on_clone();
  virtual filter* on_fork();

  virtual filter_action filter_syscall_enter(process_state& st);
  virtual filter_action filter_syscall_exit(process_state& st);

 private:
  int refs;
};

class base_filter : public filter {
 public:
  base_filter();
  virtual ~base_filter();

  virtual filter_action filter_syscall_enter(process_state& st);
};

class memory_filter : public filter {
 public:
  memory_filter();
  virtual ~memory_filter();

  virtual filter* on_fork();

  virtual filter_action filter_syscall_enter(process_state& st);
  virtual filter_action filter_syscall_exit(process_state& st);
};

class file_filter : public filter {
 public:
  file_filter();
  virtual ~file_filter();

  virtual filter_action filter_syscall_enter(process_state& st);
};

#endif // JAIL_FILTER_H
