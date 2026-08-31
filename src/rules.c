#include "rules.h"

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "alert.h"
#include "tracer.h"
#include "stat.h"
#include "score.h"

int label = 0;


static void kill_process(
    event *event,
    syscall_stat *stats
)
{
    if (event == NULL || stats == NULL)
        return;

    if (kill(event->pid, SIGKILL) == -1) {
        perror("kill");
        return;
    }

    all_stats.dangerous_events++;
    stats->killit++;
    all_stats.killit++;

    stats->label = 1;

    printf(
        "[KILLED] Process PID %d\n",
        event->pid
    );
}

void check_danger(
    pid_t pid,
    EventType type,
    char syscall[32],
    char path[256],
    int porter
)
{
    (void)porter;

    int suspicious =
        strcmp(path, "/etc/passwd") == 0 ||
        strcmp(path, "/etc/shadow") == 0 ||
        strcmp(syscall, "fork") == 0 ||
        strcmp(syscall, "clone") == 0 ||
        strcmp(syscall, "connect") == 0 ||
        strcmp(syscall, "open") == 0 ||
        strcmp(syscall, "execve") == 0 ||
        strcmp(syscall, "mprotect") == 0 ||
        strcmp(syscall, "ptrace") == 0 ||
        strcmp(syscall, "read") == 0;

    if (!suspicious)
        return;


    event e;

    memset(&e, 0, sizeof(e));

    label = 1;

    e.type = type;
    e.pid = pid;
    e.severity = CRITICAL;


    strncpy(
        e.path,
        path,
        sizeof(e.path) - 1
    );

    e.path[sizeof(e.path) - 1] = '\0';


    strncpy(
        e.syscall,
        syscall,
        sizeof(e.syscall) - 1
    );

    e.syscall[sizeof(e.syscall) - 1] = '\0';


    check_rules(&e);
}


void check_rules(event *event)
{
    if (event == NULL)
        return;

    syscall_stat *stats = get_stats(event->pid);

    if (stats == NULL)
        return;


    /*
     * Check direct access to sensitive files.
     *
     * Do not return here because we still want
     * to calculate the risk score below.
     */
    if (
        strcmp(event->path, "/etc/shadow") == 0 ||
        strcmp(event->path, "/etc/passwd") == 0
    ) {

        alert_high(
            event,
            "TRY TO ACCESS PASSWORD FILE"
        );

        kill_process(event, stats);

        stats->label = 1;
    }


    switch (event->type)
    {
    case EVENT_FILE_OPEN:

        if (stats->open > 50) {

            alert_high(
                event,
                "EXCESSIVE FILE OPEN ACTIVITY"
            );

            kill_process(event, stats);

            stats->label = 1;
        }

        break;


    case EVENT_FILE_READ:

        if (stats->read > 29) {

            alert_high(
                event,
                "EXCESSIVE FILE READ ACTIVITY"
            );

            kill_process(event, stats);

            stats->label = 1;
        }

        break;


    case EVENT_PROCESS_FORK:

        if (stats->fork > 8) {

            printf(
                "DEBUG: fork rule reached\n"
            );

            alert_high(
                event,
                "TRY TO CREATE TOO MANY PROCESSES"
            );

            kill_process(event, stats);

            stats->label = 1;
        }

        break;


    case EVENT_PROCESS_EXEC:

        if (stats->execve > 8) {

            alert_high(
                event,
                "TRY TO CHANGE THE PROGRAM"
            );

            kill_process(event, stats);

            stats->label = 1;
        }

        break;


    case EVENT_NETWORK_CONNECT:

        alert_high(
            event,
            "TRY TO CONNECT WITH SOMEONE"
        );

        kill_process(event, stats);

        stats->label = 1;

        break;


    case EVENT_NETWORK_SEND:

        alert_high(
            event,
            "TRY TO SEND SOMETHING"
        );

        kill_process(event, stats);

        stats->label = 1;

        break;


    case EVENT_MEMORY_MPROTECT:


    if (stats->mprotect> 5){
        alert_high(
            event,
            "TRY TO CHANGE MEMORY PERMISSIONS"
        );

        kill_process(event, stats);

        stats->label = 1;}
        

        break;


    case EVENT_PRCOESS_PTRACE:


        alert_high(
            event,
            "TRY TO TRACE ANOTHER PROCESS"
        );

        kill_process(event, stats);

        stats->label = 1;

        break;


    default:
        break;
    }


    /*
     * Calculate the risk of the current PID.
     *
     * This is reached even when a specific rule
     * above detected something dangerous.
     */
    int risk = compute_risk_score(stats);

 
    stats->risk_score = risk;


    if (risk >= 70 && stats->killit == 0) {
        alert_high(
            event,
            "HIGH RISK BEHAVIOR"
        );

        kill_process(event, stats);

        stats->label = 1;
    }

    else if (risk >= 40) {

        alert_high(
            event,
            "SUSPICIOUS BEHAVIOR"
        );

        stats->label = 1;
    }

    else {

        /*
         * Don't overwrite an already dangerous label.
         */
        if (stats->label != 1)
            stats->label = 0;
    }
}
