#include "stat.h"

#include <string.h>
#include <stdio.h>

struct main_stats all_stats = {0};
syscall_stat stats_table[MAX_TRACED] = {0};

syscall_stat *get_stats(pid_t pid)
{
  
    // if the pid exist 
    for (int i = 0; i < MAX_TRACED; i++) {

        if (stats_table[i].used &&
            stats_table[i].pid == pid) {

            return &stats_table[i];
        }
    }

    // if pid does not exist 
    for (int i = 0; i < MAX_TRACED; i++) {

        if (!stats_table[i].used) {

            memset(
                &stats_table[i],
                0,
                sizeof(syscall_stat)
            );

            stats_table[i].used = 1;
            stats_table[i].pid = pid;

            return &stats_table[i];
        }
    }

    return NULL;
}



void remove_sta(pid_t pid)
{
    for (int i = 0; i < MAX_TRACED; i++) {

        if (stats_table[i].used &&
            stats_table[i].pid == pid) {

            stats_table[i].used = 0;

            return;
        }
    }
}


void counter_main(syscall_stat *stats)
{
    if (stats == NULL){
        perror("error in countermain");
        return;}

    all_stats.file     += stats->file;
    all_stats.process  += stats->process;
    all_stats.network  += stats->network;

    all_stats.fork     += stats->fork;
    all_stats.connect  += stats->connect;
    all_stats.execve   += stats->execve;
    all_stats.read     += stats->read;
    all_stats.open     += stats->open;
    all_stats.close    += stats->close;
    all_stats.ptrace   += stats->ptrace;

    all_stats.memory   += stats->memory;
    all_stats.mprotect += stats->mprotect;
    all_stats.killit   += stats->killit;
    all_stats.label    +=stats->label;
}
void record_process_score(syscall_stat *stats)
{
    if (stats == NULL)
        return;

    if (stats->used == 2)
        return;


    all_stats.total_risk_score += stats->risk_score;
    all_stats.processes_seen++;


    // 2 : mean the score was recorded
    stats->used = 2;
}

/*int calculate_main_score(void)
{
    if (all_stats.processes_seen == 0)
        return 0;


    all_stats.main_score =
        all_stats.total_risk_score /
        all_stats.processes_seen;


    return all_stats.main_score;
}*/


void reset_stats(void)
{
    memset(
        stats_table,
        0,
        sizeof(stats_table)
    );


    memset(
        &all_stats,
        0,
        sizeof(all_stats)
    );
}