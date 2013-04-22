#ifndef __REPORT_H
#define __REPORT_H

#include <string>

class process_state;
struct rusage;

bool init_report();
bool finalize_report();

void log_exit(pid_t pid, const exit_data& data, bool final);
void log_blocked_syscall(process_state& st);
void log_violation(pid_t pid, const std::string& message);
void log_error(pid_t pid, const std::string& message);
void log_info(pid_t pid, int level, const std::string& message);

#endif
