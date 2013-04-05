#include <iostream>
#include <vector>
#include <cstdlib>
#include <cstdio>

#include "config.h"
#include "process_state.h"

using namespace std;

FILE * fout = NULL;

bool init_report() {
  return !get_report() || (fout = fopen(get_report_file().c_str(), "w"));
}

void log_exit_status(pid_t pid, int exit_status) {
  if(fout) {
    fprintf(fout, "[%5d] exit_status  %d\n", pid, exit_status);
    fflush(fout);
  }
}

void log_term_signal(pid_t pid, int term_signal) {
  if(fout) {
    fprintf(fout, "[%5d] term_signal  %d\n", pid, term_signal);
    fflush(fout);
  }
}

void log_blocked_syscall(process_state& st) {
  if(fout) {
    fprintf(fout, "[%5d] syscall      %s(%lX,%lX,%lX,%lX,%lX,%lX)\n",
            st.get_pid(), st.get_syscall_name(st.get_syscall()),
            st.get_param(0), st.get_param(1), st.get_param(2),
            st.get_param(3), st.get_param(4), st.get_param(5));
    fflush(fout);
  }
}


void log_violation(pid_t pid, const string & message) {
  if(fout) {
    fprintf(fout, "[%5d] violation    %s\n", pid, message.c_str());
    fflush(fout);
  }
}

void log_error(pid_t pid, const string & message) {
  if(fout) {
    fprintf(fout, "[%5d] error        %s\n", pid, message.c_str());
    fflush(fout);
  }
}

void log_info(pid_t pid, int level, const string & message) {
  if(fout && level <= get_log_level()) {
    fprintf(fout, "[%5d] log(%d)       %s\n", pid, level, message.c_str());
    fflush(fout);
  }
}
