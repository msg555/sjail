#ifndef JAIL_FILTER_H
#define JAIL_FILTER_H

#include <list>
#include <sys/types.h>

#include "range_tree.h"
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
  
  virtual void on_exit(pid_t pid);
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

  virtual void on_exit(pid_t pid);
  virtual filter* on_fork();

  virtual filter_action filter_syscall_enter(process_state& st);
  virtual filter_action filter_syscall_exit(process_state& st);

 private:
  unsigned long heap_base;
  unsigned long heap_end;
  unsigned long max_memory;
  range_tree<unsigned long> mappings;

  static unsigned long page_size;
};

class file_filter : public filter {
 public:
  file_filter();
  virtual ~file_filter();

  virtual filter_action filter_syscall_enter(process_state& st);
};

class exec_filter : public filter {
 public:
  exec_filter();
  virtual ~exec_filter();

  virtual filter_action filter_syscall_enter(process_state& st);
};

class net_filter : public filter {
 public:
  net_filter();
  virtual ~net_filter();

  virtual filter_action filter_syscall_enter(process_state& st);
};

#endif // JAIL_FILTER_H
