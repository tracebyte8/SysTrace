#ifndef STAT_H
#define STAT_H

typedef struct {
    int file;
    int process;
    int network;

    int fork;
    int connect;
    int execve;
    int read;
    int open;
    int close;

    int memory;
    int chmod;
    int killit;
    int label;
} syscall_stat;

extern syscall_stat stats;
void reset_stats(void);


#endif