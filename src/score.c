#include "score.h"
#include "stat.h"
#include <stdio.h>
#include <stddef.h>

/* how "loud" a signal each category is, not how often it fires */
#define W_CONNECT   5.0
#define W_NETWORK   4.0
#define W_PTRACE    6.0
#define W_EXECVE    3.0
#define W_MPROTECT  3.0
#define W_FORK      2.0
#define W_PROCESS   1.5
#define W_OPEN      0.5
#define W_MEMORY    0.5
#define W_FILE      0.3
#define W_READ      0.2
#define W_CLOSE     0.1

#define W_MAX       6.0

int compute_risk_score(syscall_stat *stats)
{
    if (stats == NULL)
        return 0;

    long total =
        stats->file +
        stats->process +
        stats->network +
        stats->fork +
        stats->connect +
        stats->execve +
        stats->read +
        stats->open +
        stats->close +
        stats->memory +
        stats->mprotect +
        stats->ptrace;

    if (total == 0)
        return stats->killit ? 90 : 0;

    double risky =
        stats->connect  * W_CONNECT +
        stats->network  * W_NETWORK +
        stats->ptrace   * W_PTRACE +
        stats->execve   * W_EXECVE +
        stats->mprotect * W_MPROTECT +
        stats->fork     * W_FORK +
        stats->process  * W_PROCESS +
        stats->open     * W_OPEN +
        stats->memory   * W_MEMORY +
        stats->file     * W_FILE +
        stats->read     * W_READ +
        stats->close    * W_CLOSE;

    double max_possible = total * W_MAX;

    int score = (int)((risky / max_possible) * 100);

    /*
     * killit means the rule engine has
     * explicitly identified dangerous behavior.
     */
    if (stats->killit > 0 && score < 90)
        score = 90;

    if (score > 100)
        score = 100;

    return score;
}

int compute_main_risk_score(void)
{
    syscall_stat stats = {0};

    stats.file     = all_stats.file;
    stats.process  = all_stats.process;
    stats.network  = all_stats.network;

    stats.fork     = all_stats.fork;
    stats.connect  = all_stats.connect;
    stats.execve   = all_stats.execve;
    stats.read     = all_stats.read;
    stats.open     = all_stats.open;
    stats.close    = all_stats.close;
    stats.ptrace   = all_stats.ptrace;

    stats.memory   = all_stats.memory;
    stats.mprotect = all_stats.mprotect;

    stats.killit   = all_stats.killit;

    return compute_risk_score(&stats);
}