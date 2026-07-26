#ifndef FILE_MONITOR_H
#define FILE_MONITOR_H

#include <sys/types.h>
#include <sys/user.h>

void handle_file_syscall(pid_t pid,
                         struct user_regs_struct *regs,
                         int entering);

#endif