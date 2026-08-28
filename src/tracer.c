#include "tracer.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <signal.h>

#include "syscall.h"
#include "file_monitor.h"
#include "process_monitor.h"
#include "memory_monitor.h"
#include "network_monitor.h"
#include "fd_tables.h"
#include "alert.h"
#include "event.h"
#include "rules.h"
#include "stat.h"
#include "dataset.h"
#include "isolate.h"

/*
 * tracer.c
 *
 * Core tracing module.
 *
 * Creates the isolated target process, stores traced processes,
 * and monitors their system calls using ptrace.
 */
struct traced_process {
    pid_t pid;
    pid_t parent;
    int entering;
};

void remove_process(struct traced_process traced[],
                     int *count,
                     int index)
{
    for (int i = index; i < *count - 1; i++)
        traced[i] = traced[i + 1];

    (*count)--;
}

int set_trace_options(pid_t pid)
{
    if (ptrace(PTRACE_SETOPTIONS,
               pid,
               0,
               PTRACE_O_TRACESYSGOOD |
               PTRACE_O_TRACEFORK |
               PTRACE_O_TRACEVFORK |
               PTRACE_O_TRACECLONE |
               PTRACE_O_TRACEEXEC |
               PTRACE_O_TRACEEXIT) == -1)
    {
        perror("PTRACE_SETOPTIONS");
        return -1;
    }

    return 1;
}

pid_t trace(char *program)
{
    /*
     * Build the argument array required by create_namespace().
     * The sandbox child will execute program as target_argv[0].
     */
    char *target_argv[] = {
        program,
        NULL
    };

    /*
     * Create the isolated child process.
     * create_namespace() returns the child's PID to the tracer.
     */
    pid_t root_pid = create_namespace(target_argv);

    int status;

    open_alert();

    if (root_pid == -1) {
        perror("create_namespace");
        close_alert();
        return -1;
    }

    /*
     * Store the initial sandbox process in the traced process list.
     */
    struct traced_process traced[128];
    int traced_count = 1;

    traced[0].pid = root_pid;
    traced[0].entering = 1;
    traced[0].parent = 0;

    /*
     * The sandbox child calls PTRACE_TRACEME and stops with SIGSTOP.
     * Wait for that initial stop before configuring ptrace options.
     */
    if (waitpid(root_pid, &status, 0) == -1) {
        perror("waitpid");
        close_alert();
        return -1;
    }

    printf("DEBUG: initial status=0x%x\n", status);

    if (!WIFSTOPPED(status)) {
        fprintf(stderr,
                "DEBUG: child did not stop, status=0x%x\n",
                status);
        close_alert();
        return -1;
    }

    printf("DEBUG: child stopped with signal=%d\n",
           WSTOPSIG(status));

    if (set_trace_options(root_pid) == -1) {
        fprintf(stderr,
                "DEBUG: SETOPTIONS failed for pid=%d\n",
                root_pid);
        close_alert();
        return -1;
    }

    printf("DEBUG: SETOPTIONS succeeded\n");

    struct user_regs_struct regs;

    /* Tracing loop until the child process exits. */
    while (1) {

        for (int i = 0; i < traced_count; i++) {
            ptrace(PTRACE_SYSCALL, traced[i].pid, 0, 0);
        }

        /* Wait for whichever traced process stops next. */
        pid_t current_pid = waitpid(-1, &status, 0);

        if (current_pid == -1)
            break;

        /*
         * Find the index of the process that stopped in the
         * traced array, so its entering/exiting state can be used.
         * If not found, skip to the next iteration of the loop.
         */
        int current = -1;

        for (int i = 0; i < traced_count; i++) {
            if (traced[i].pid == current_pid) {
                current = i;
                break;
            }
        }

        if (current == -1) {
            fprintf(stderr,
                    "DEBUG: PID %d not found in traced[]\n",
                    current_pid);
            continue;
        }

        fprintf(syscall_file, "PID=%d PPID=%d STATUS=0x%x EVENT=%u SIG=%d\n",
                current_pid,
                traced[current].parent,
                status,
                status >> 16,
                WSTOPSIG(status));

        /* If this pid is not in the traced array, skip it. */
        if (current == -1)
            continue;

        /*
         * If the process exited, remove it from the traced array
         * and continue to the next iteration of the loop.
         */
        if (WIFEXITED(status)) {
            remove_process(traced,
                           &traced_count,
                           current);

            if (traced_count == 0)
                break;

            continue;
        }

        /* If the process is not stopped, ignore it. */
        if (!WIFSTOPPED(status))
            continue;

        /* Check whether this stop is a ptrace event. */
        unsigned int event = status >> 16;

        if (event == PTRACE_EVENT_FORK ||
            event == PTRACE_EVENT_VFORK ||
            event == PTRACE_EVENT_CLONE)
        {
            unsigned long new_pid;

            ptrace(PTRACE_GETEVENTMSG,
                   current_pid,
                   0,
                   &new_pid);

            fprintf(syscall_file, "Parent %d -> Child %lu\n",
                    current_pid,
                    new_pid);

            traced[traced_count].pid = new_pid;
            traced[traced_count].entering = 1;
            traced[traced_count].parent = current_pid;
            traced_count++;

            printf("tests ");
        if (set_trace_options(new_pid) == -1) {
            perror("PTRACE_SETOPTIONS");
        }    
    }

        /* Ignore everything except syscall stops. */
        if (WSTOPSIG(status) != (SIGTRAP | 0x80))
            continue;

        if (ptrace(PTRACE_GETREGS,
                   current_pid,
                   0,
                   &regs) == -1)
        {
            perror("PTRACE_GETREGS");
            break;
        }

        if (traced[current].entering) {

            fprintf(syscall_file, "ENTER %s (%lld)\n",
                    syscall_name(regs.orig_rax),
                    (long long)regs.orig_rax);

            handle_file_syscall(current_pid, &regs, 1);
            handle_process_syscall(current_pid, &regs, 1);
            handle_memory_syscall(current_pid, &regs, 1);
            handle_network_syscall(current_pid, &regs, 1);

        } else {

            handle_file_syscall(current_pid, &regs, 0);
            handle_process_syscall(current_pid, &regs, 0);
            handle_memory_syscall(current_pid, &regs, 0);
            handle_network_syscall(current_pid, &regs, 0);

            if (regs.orig_rax == SYS_openat ||
                regs.orig_rax == SYS_open) {

                char *name = search_fd((int)regs.rax);

                fprintf(syscall_file, "EXIT  %s return=%lld",
                        syscall_name(regs.orig_rax),
                        (long long)regs.rax);

                if (name != NULL)
                    fprintf(syscall_file, " (%s)", name);

                fprintf(syscall_file, "\n");

            } else {

                fprintf(syscall_file, "EXIT  %s return=%lld\n",
                        syscall_name(regs.orig_rax),
                        (long long)regs.rax);
            }
        }

        fprintf(syscall_file, "----------------------------------\n");

        traced[current].entering = !traced[current].entering;
    }

    close_alert();
    return (root_pid);
}