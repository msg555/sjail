#ifndef JAIL_MEMORY_H
#define JAIL_MEMORY_H

#include <sys/types.h>
#include <stdint.h>

class process_state;

bool initialize_safe_memory();

bool map_memory_unwritable();

void* read_from_pid(pid_t pid, intptr_t remote_addr, size_t len);

void* read_from_pid_to_null(pid_t pid, intptr_t remote_addr);

bool install_safe_memory(pid_t pid, process_state& st);

bool install_safe_memory_result(pid_t pid, process_state& st);

intptr_t proc_safe_memory(pid_t pid, void* local_ptr);

bool safemem_filter_mapcall(process_state& st);

#endif // JAIL_MEMORY_H
