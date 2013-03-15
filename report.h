#ifndef __REPORT_H
#define __REPORT_H

#include <iostream>

using namespace std;

bool init_report();
bool finalize_report();

void log_exit_status(int exit_status);
void log_term_signal(int term_signal);
void log_blocked_syscall(unsigned long sys_num, unsigned long result,
                         unsigned long param1,  unsigned long param2,
                         unsigned long param3,  unsigned long param4,
                         unsigned long param5,  unsigned long param6);
void log_violation(const string & message);
void log_error(const string & message);
void log_info(int level, const string & message);

#endif
