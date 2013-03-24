#include <iostream>
#include <vector>
#include <cstdlib>
#include <cstdio>

#include "config.h"
#include "syscall_tab.h"

using namespace std;

FILE * fout = NULL;

bool init_report() {
  return !get_report() || (fout = fopen(get_report_file().c_str(), "w"));
}

bool finalize_report(const rusage & resources){
  fprintf(fout, "user_time_sec:%llu.%06llu\n", resources.ru_utime.tv_sec, resources.ru_utime.tv_usec);
  fprintf(fout, "system_time_sec:%llu.%06llu\n", resources.ru_stime.tv_sec, resources.ru_stime.tv_usec);
  fprintf(fout, "max_memory_kb:%llu\n", resources.ru_maxrss);
  fflush(fout);
  return !fclose(fout);
}

void log_exit_status(int exit_status) {
  if(fout) {
    fprintf(fout, "exit_status:%d\n", exit_status);
    fflush(fout);
  }
}

void log_term_signal(int term_signal) {
  if(fout) {
    fprintf(fout, "term_signal:%d\n", term_signal);
    fflush(fout);
  }
}

void log_blocked_syscall(unsigned long sys_num, unsigned long result,
                         unsigned long param1,  unsigned long param2,
                         unsigned long param3,  unsigned long param4,
                         unsigned long param5,  unsigned long param6) {
  if(fout) {
    fprintf(fout, "syscall:%s(%lu,%lu,%lu,%lu,%lu,%lu)\n",
            get_syscall_name(sys_num).c_str(), param1,
            param2, param3, param4, param5, param6);
    fflush(fout);
  }
}


void log_violation(const string & message) {
  if(fout) {
    fprintf(fout, "violation:%s\n", message.c_str());
    fflush(fout);
  }
}

void log_error(const string & message) {
  if(fout) {
    fprintf(fout, "error:%s\n", message.c_str());
    fflush(fout);
  }
}

void log_info(int level, const string & message) {
  if(fout && level <= get_log_level()) {
    fprintf(fout, "log(%d):%s\n", level, message.c_str());
    fflush(fout);
  }
}

