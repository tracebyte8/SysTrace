#include <stdio.h>
#include "stat.h"
#include "dataset.h"
#include "rules.h"
#include "score.h"
void save_dataset(const char *program, int label, pid_t pid)
{
   /* syscall_stat *stats = get_stats(pid);
    if (stats == NULL) {
        fprintf(stderr, "save_dataset: no stats for pid %d\n", pid);
        return;
}*/

    FILE *fp = fopen("features.json", "a");   /* append, don't clobber */
    if (fp == NULL) {
        perror("features.json");
        return;
    }
int allscore = compute_main_risk_score();
    printf("%d all scores !! \n",allscore);

printf("DATASET: program=%s file=%d process=%d network=%d fork=%d connect=%d "
       "execve=%d read=%d open=%d close=%d memory=%d mprotect=%d "
       "ptrace=%d label=%d\n",
       program,
       all_stats.file,
       all_stats.process,
       all_stats.network,
       all_stats.fork,
       all_stats.connect,
       all_stats.execve,
       all_stats.read,
       all_stats.open,
       all_stats.close,
       all_stats.memory,
       all_stats.mprotect,
       all_stats.ptrace,
       label);

fprintf(fp,
    "{\"program\": \"%s\", \"file\": %d, \"process\": %d, \"network\": %d, "
    "\"fork\": %d, \"connect\": %d, \"execve\": %d, \"read\": %d, "
    "\"open\": %d, \"close\": %d, \"memory\": %d, \"mprotect\": %d, "
    "\"ptrace\": %d, \"label\": %d}\n",
    program,
    all_stats.file,
    all_stats.process,
    all_stats.network,
    all_stats.fork,
    all_stats.connect,
    all_stats.execve,
    all_stats.read,
    all_stats.open,
    all_stats.close,
    all_stats.memory,
    all_stats.mprotect,
    all_stats.ptrace,
    label);

    fclose(fp);
}