#include "rules.h"
#include "alert.h"
#include <string.h>
#include <signal.h>
#include "tracer.h"
#include "stat.h"
#include "score.h"

int label = 0;

static void kill_process(event *event, syscall_stat *stats)
{
    if (event == NULL || stats == NULL)
        return;

    if (kill(event->pid, SIGKILL) == -1) {
        perror("kill");
        return;
    }

    stats->killit++;
    stats->label = 1;

    printf("[KILLED] Process PID %d\n", event->pid);
}
void check_danger(pid_t pid,
                  EventType type,
                  char syscall[32],
                  char path[256],
                  int porter)
{
    int suspicious =
        strcmp(path, "/etc/passwd") == 0 ||
        strcmp(path, "/etc/shadow") == 0 ||
        strcmp(syscall, "fork") == 0 ||
        strcmp(syscall, "clone") == 0 ||
        strcmp(syscall, "connect") == 0 ||
        strcmp(syscall, "open") == 0 ||
        strcmp(syscall, "read") == 0;

    if (suspicious) {

        event e;
        label = 1;
        e.type = type;

        strncpy(e.path, path, sizeof(e.path) - 1);
        e.path[sizeof(e.path) - 1] = '\0';

        e.pid = pid;

        strncpy(e.syscall, syscall, sizeof(e.syscall) - 1);
        e.syscall[sizeof(e.syscall) - 1] = '\0';

        e.severity = CRITICAL;

        check_rules(&e);
    }
}

void check_rules(event *event)
{
    if (event == NULL)
        return;

    syscall_stat *stats = get_stats(event->pid);

    if (stats == NULL)
        return;

    if (strcmp(event->path, "/etc/shadow") == 0 ||
        strcmp(event->path, "/etc/passwd") == 0) {

        alert_high(event, "TRY TO ACCESS PASSWORD FILE");
        kill_process(event, stats);

        stats->label = 1;
        return;
    }

    switch (event->type) {

    case EVENT_FILE_OPEN:
        if (stats->open > 100) {
            alert_high(event, "EXCESSIVE FILE OPEN ACTIVITY");
            kill_process(event, stats);
            stats->label = 1;
            return;
        }
        break;

    case EVENT_FILE_READ:
        if (stats->read > 100) {
            alert_high(event, "EXCESSIVE FILE READ ACTIVITY");
            kill_process(event, stats);
            stats->label = 1;
            return;
        }
        break;

    case EVENT_PROCESS_FORK:
        if (stats->fork > 8) {
            alert_high(event, "TRY TO CREATE TOO MANY PROCESSES");
            kill_process(event, stats);
            stats->label = 1;
            return;
        }
        break;

    case EVENT_PROCESS_EXEC:
        alert_high(event, "TRY TO CHANGE THE PROGRAM");
        kill_process(event, stats);
        stats->label = 1;
        return;

    case EVENT_NETWORK_CONNECT:
        alert_high(event, "TRY TO CONNECT WITH SOMEONE");
        kill_process(event, stats);
        stats->label = 1;
        return;

    case EVENT_NETWORK_SEND:
        alert_high(event, "TRY TO SEND SOMETHING");
        kill_process(event, stats);
        stats->label = 1;
        return;

    case EVENT_MEMORY_MPROTECT:
        alert_high(event, "TRY TO CHANGE MEMORY PERMISSIONS");
        kill_process(event, stats);
        stats->label = 1;
        return;

    case EVENT_PRCOESS_PTRACE:
        alert_high(event, "TRY TO TRACE ANOTHER PROCESS");
        kill_process(event, stats);
        stats->label = 1;
        return;

    default:
        break;
    }

    int risk = compute_risk_score(stats);

    stats->risk_score = risk;

    if (risk >= 70) {
        alert_high(event, "HIGH RISK BEHAVIOR");
        kill_process(event, stats);
        stats->label = 1;
    }
    else if (risk >= 40) {
        alert_high(event, "SUSPICIOUS BEHAVIOR");
        stats->label = 1;
    }
    else {
        stats->label = 0;
    }
}