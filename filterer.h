#ifndef __FILTERER_H
#define __FILTERER_H

bool read_from_pid(char * dst_addr, unsigned long remote_src_addr, long len, int pid);
bool read_from_pid_to_null(char * dst_addr, unsigned long remote_src_addr, long max_len, int pid);

void process_system_call(int pid);
bool process_network_call(int call_num, unsigned long socket_param[6], int pid);
void process_network_exit(int call_num, unsigned long result, unsigned long socket_param[6], int pid);

bool process_fileopen(unsigned long param1, unsigned long param2, int pid);
#endif
