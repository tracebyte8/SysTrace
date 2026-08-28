#ifndef STAT_H
#define STAT_H
#include <sys/types.h>
#include <stdio.h>
#define MAX_TRACED 128
typedef struct {
    pid_t pid;
    int used;


    int file;
    int process;
    int network;

    int fork;
    int connect;
    int execve;
    int read;
    int open;
    int close;
    int ptrace;

    int memory;
    int mprotect;
    int killit;
    int label;
    int risk_score;
} syscall_stat;

extern syscall_stat stats_table[MAX_TRACED];
syscall_stat *get_stats(pid_t pid);
void remove_sta(pid_t pid);
void reset_stats(void);


#endif