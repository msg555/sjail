#ifndef __REPORT_H
#define __REPORT_H

#include <string>

class process_state;
struct rusage;

bool init_report();
bool finalize_report();

void log_exit_status(pid_t pid, int exit_status);
void log_term_signal(pid_t pid, int term_signal);
void log_blocked_syscall(process_state& st);
void log_violation(pid_t pid, const std::string& message);
void log_error(pid_t pid, const std::string& message);
void log_info(pid_t pid, int level, const std::string& message);
void log_resources(pid_t pid, rusage* resources);

#endif
