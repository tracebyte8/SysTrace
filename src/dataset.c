#include <stdio.h>
#include "stat.h"
#include "dataset.h"
#include "rules.h"

void save_dataset(const char *program, int label, pid_t pid)
{
    syscall_stat *stats = get_stats(pid);
    if (stats == NULL) {
        fprintf(stderr, "save_dataset: no stats for pid %d\n", pid);
        return;
    }

    FILE *fp = fopen("features.json", "a");   /* append, don't clobber */
    if (fp == NULL) {
        perror("features.json");
        return;
    }

    printf("DATASET: program=%s file=%d process=%d network=%d fork=%d connect=%d "
           "execve=%d read=%d open=%d close=%d memory=%d mprotect=%d "
           "ptrace=%d label=%d\n",
           program, stats->file, stats->process, stats->network, stats->fork,
           stats->connect, stats->execve, stats->read, stats->open,
           stats->close, stats->memory, stats->mprotect, stats->ptrace, label);

    fprintf(fp,
        "{\"program\": \"%s\", \"file\": %d, \"process\": %d, \"network\": %d, "
        "\"fork\": %d, \"connect\": %d, \"execve\": %d, \"read\": %d, "
        "\"open\": %d, \"close\": %d, \"memory\": %d, \"mprotect\": %d, "
        "\"ptrace\": %d, \"label\": %d}\n",
        program, stats->file, stats->process, stats->network, stats->fork,
        stats->connect, stats->execve, stats->read, stats->open,
        stats->close, stats->memory, stats->mprotect, stats->ptrace, label);

    fclose(fp);
}