#include "stat.h"
#include <stdio.h>
#include <string.h>
syscall_stat stats_table[MAX_TRACED];

syscall_stat *get_stats(pid_t pid){

for(int i =0 ; i<MAX_TRACED ; i++){
    if(stats_table[i].used && stats_table[i].pid==pid){
        return &stats_table[i];
    }
}

    



    for (int i = 0; i < MAX_TRACED; i++) {
        if (!stats_table[i].used) {
            memset(&stats_table[i], 0, sizeof(syscall_stat));
            stats_table[i].used = 1;
            stats_table[i].pid = pid;
            return &stats_table[i];
        }
    }

    return NULL; // table full — shouldn't happen if MAX_TRACED matches tracer.c's traced[128]
}

void remove_sta(pid_t pid){
    for (int i =0 ; i < MAX_TRACED ;i++){
        if (stats_table[i].used && stats_table[i].pid==pid){
            stats_table[i].used=0;
        }
    }
}

syscall_stat stats = {0};

void reset_stats(void)
{
    memset(stats_table, 0, sizeof(stats_table));}