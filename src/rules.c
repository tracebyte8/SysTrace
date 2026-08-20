#include "rules.h"
#include "alert.h"
#include <string.h>
#include <signal.h>
#include "tracer.h"
#include "stat.h"

// rules.c is mini rule engine that filter simple danger syscall.
// block process and save it in alert.json and kill the process !.
int label =0;
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
        strcmp(syscall, "read") == 0 ;
    if (suspicious) {

        event e;
        label = 1 ;
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
    switch (event->type) {

        // open
        case EVENT_FILE_OPEN:

            if (stats.open > 100) {

                alert_high(event,
                           "TRY TO OPEN FILE FOR PASSWORDS");

                if (kill(event->pid, SIGKILL) == -1) {
                    perror("kill");
                }

                stats.killit++;

            } else {
                label = 0;
            }

            break;


        // read
        case EVENT_FILE_READ:

            if (stats.read <= 100) {
              label =0;
            } else if (stats.read > 100) {

                alert_high(event,
                           "TRY TO READ PASSWORDS");

                if (kill(event->pid, SIGKILL) == -1) {
                    perror("kill");
                }

                stats.killit++;
            }

            break;


        // fork
        case EVENT_PROCESS_FORK:

            if (stats.fork > 8) {

                alert_high(event,
                           "TRY TO CREATE ANOTHER PROCESS");

                if (kill(event->pid, SIGKILL) == -1) {
                    perror("kill");
                }

                stats.killit++;

            } else {
                label = 0;
            }

            break;


        // execve
        case EVENT_PROCESS_EXEC:

            alert_high(event,
                       "TRY TO CHANGE THE PROG MISSION");

            if (kill(event->pid, SIGKILL) == -1) {
                perror("kill");
            }

            stats.killit++;

            break;


        // connect
        case EVENT_NETWORK_CONNECT:

            alert_high(event,
                       "TRY TO CONNECT WITH SOMEONE");

            if (kill(event->pid, SIGKILL) == -1) {
                perror("kill");
            }

            stats.killit++;

            break;


        // sendto
        case EVENT_NETWORK_SEND:

            alert_high(event,
                       "TRY TO SEND SOMETHING");

            if (kill(event->pid, SIGKILL) == -1) {
                perror("kill");
            }

            stats.killit++;

            break;


        // mprotect
        case EVENT_MEMORY_MPROTECT:

            alert_high(event,
                       "TRY TO SEND SOMETHING");

            if (kill(event->pid, SIGKILL) == -1) {
                perror("kill");
            }

            stats.killit++;

            break;


        default:
            break;
    }
}