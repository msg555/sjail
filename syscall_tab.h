#ifndef __SYSCALL_TAB_H
#define __SYSCALL_TAB_H

#include <iostream>
#include <string.h>
#include <sys/syscall.h>
#include <bits/wordsize.h>

using namespace std;

string get_syscall_name(int sys_num);

#endif


