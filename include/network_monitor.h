#ifndef NETWORK_MONITOR_H
#define NETWORK_MONITOR_H

#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/user.h>


void handle_network_syscall(pid_t pid,
                            struct user_regs_struct *regs,
                            int entering);

#endif