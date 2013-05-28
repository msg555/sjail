#ifndef JAIL_MEMORY_H
#define JAIL_MEMORY_H

#include <sys/types.h>
#include <stdint.h>

struct pdata;

bool safemem_init();

bool safemem_map_unwritable();

void* safemem_read_pid(pid_data& pdata, uintptr_t remote_addr, size_t len);

void* safemem_read_pid_to_null(pid_data& pdata, uintptr_t remote_addr);

uintptr_t safemem_remote_addr(pid_data& pdata, void* local_ptr);

void safemem_reset(pid_data& pdata);

#endif // JAIL_MEMORY_H
