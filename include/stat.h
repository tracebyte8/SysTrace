#ifndef STAT_H
#define STAT_H

#include <sys/types.h>

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


/*
 * Global statistics for the whole traced program
 */
struct main_stats {
    int processes_seen;
    int total_risk_score;
    int main_score;

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
    int dangerous_events;

    int label;

};

extern struct main_stats all_stats;

extern syscall_stat stats_table[MAX_TRACED];

syscall_stat *get_stats(pid_t pid);
void counter_main(syscall_stat *stats);

 // Remove a PID from the active statistics table.
void remove_sta(pid_t pid);

void reset_stats(void);


 // Call this when a process finishes.
 
void record_process_score(syscall_stat *stats);


/*
 * Calculate the average risk score of all
 * processes that have finished.
 */
int calculate_main_score(void);

#endif