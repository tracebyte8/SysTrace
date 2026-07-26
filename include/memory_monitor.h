#ifndef MEMORY_MONITOR_H
#define MEMORY_MONITOR_H  
#include <sys/types.h>
#include <sys/user.h>
#include <stdio.h>
void handle_memory_syscall(pid_t pid, struct user_regs_struct *regs, int entering);

#endif 