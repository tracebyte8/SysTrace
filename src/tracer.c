#include "tracer.h"

#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <signal.h>
#include <errno.h>

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

struct traced_process {
    pid_t pid;
    pid_t parent;
    int entering;
};

void remove_process(
    struct traced_process traced[],
    int *count,
    int index
)
{
    for (int i = index; i < *count - 1; i++)
        traced[i] = traced[i + 1];

    (*count)--;
}

int set_trace_options(pid_t pid)
{
    if (ptrace(
            PTRACE_SETOPTIONS,
            pid,
            0,
            PTRACE_O_TRACESYSGOOD |
            PTRACE_O_TRACEFORK |
            PTRACE_O_TRACEVFORK |
            PTRACE_O_TRACECLONE |
            PTRACE_O_TRACEEXEC |
            PTRACE_O_TRACEEXIT
        ) == -1)
    {
        perror("PTRACE_SETOPTIONS");
        return -1;
    }

    return 1;
}

pid_t trace(char *program)
{
    char *target_argv[] = {
        program,
        NULL
    };

    pid_t root_pid = create_namespace(target_argv);

    int status;

    open_alert();

    if (root_pid == -1) {
        perror("create_namespace");
        close_alert();
        return -1;
    }

    struct traced_process traced[128];

    int traced_count = 1;

    traced[0].pid = root_pid;
    traced[0].entering = 1;
    traced[0].parent = 0;


    if (waitpid(root_pid, &status, 0) == -1) {
        perror("waitpid");
        close_alert();
        return -1;
    }

    printf(
        "DEBUG: initial status=0x%x\n",
        status
    );

    if (!WIFSTOPPED(status)) {
        fprintf(
            stderr,
            "DEBUG: child did not stop, status=0x%x\n",
            status
        );

        close_alert();
        return -1;
    }

    printf(
        "DEBUG: child stopped with signal=%d\n",
        WSTOPSIG(status)
    );


    if (set_trace_options(root_pid) == -1) {
        fprintf(
            stderr,
            "DEBUG: SETOPTIONS failed for pid=%d\n",
            root_pid
        );

        close_alert();
        return -1;
    }

    printf("DEBUG: SETOPTIONS succeeded\n");


    struct user_regs_struct regs;


    /*
     * Start the root process.
     */
    if (ptrace(
            PTRACE_SYSCALL,
            root_pid,
            0,
            0
        ) == -1)
    {
        perror("PTRACE_SYSCALL");
        close_alert();
        return -1;
    }


    while (traced_count > 0) {

        /*
         * Wait for any traced process.
         */
        pid_t current_pid = waitpid(
            -1,
            &status,
            0
        );

        if (current_pid == -1) {

            if (errno == EINTR)
                continue;

            perror("waitpid");
            break;
        }


        /*
         * Find process in traced[].
         */
        int current = -1;

        for (int i = 0; i < traced_count; i++) {

            if (traced[i].pid == current_pid) {
                current = i;
                break;
            }
        }


        /*
         * A child should already have been registered
         * from PTRACE_EVENT_FORK/CLONE.
         *
         * If we don't know it, don't try to process it.
         */
        if (current == -1) {

            fprintf(
                stderr,
                "DEBUG: PID %d not found in traced[]\n",
                current_pid
            );

            /*
             * Still let the unknown process continue.
             */
            if (WIFSTOPPED(status)) {

                ptrace(
                    PTRACE_SYSCALL,
                    current_pid,
                    0,
                    0
                );
            }

            continue;
        }


        fprintf(
            syscall_file,
            "PID=%d PPID=%d STATUS=0x%x EVENT=%u SIG=%d\n",
            current_pid,
            traced[current].parent,
            status,
            status >> 16,
            WSTOPSIG(status)
        );


        /*
         * Process exited.
         */
        if (
            WIFEXITED(status) ||
            WIFSIGNALED(status)
        )
        {
            printf(
                "Process %d finished\n",
                current_pid
            );

            remove_process(
                traced,
                &traced_count,
                current
            );

            if (traced_count == 0)
                break;

            continue;
        }


        if (!WIFSTOPPED(status))
            continue;


        /*
         * ptrace event.
         */
        unsigned int event = status >> 16;


        if (
            event == PTRACE_EVENT_FORK ||
            event == PTRACE_EVENT_VFORK ||
            event == PTRACE_EVENT_CLONE
        )
        {
            unsigned long new_pid = 0;

            if (
                ptrace(
                    PTRACE_GETEVENTMSG,
                    current_pid,
                    0,
                    &new_pid
                ) == -1
            )
            {
                perror("PTRACE_GETEVENTMSG");
            }
            else {

                fprintf(
                    syscall_file,
                    "Parent %d -> Child %lu\n",
                    current_pid,
                    new_pid
                );


                if (traced_count < 128) {

                    traced[traced_count].pid =
                        (pid_t)new_pid;

                    traced[traced_count].parent =
                        current_pid;

                    traced[traced_count].entering = 1;

                    traced_count++;

                    printf(
                        "[TRACE] parent=%d child=%lu\n",
                        current_pid,
                        new_pid
                    );
                }
                else {

                    fprintf(
                        stderr,
                        "Maximum traced processes reached\n"
                    );

                    kill(
                        (pid_t)new_pid,
                        SIGKILL
                    );
                }
            }


            /*
             * Continue parent after ptrace event.
             */
            ptrace(
                PTRACE_SYSCALL,
                current_pid,
                0,
                0
            );

            /*
             * New child is automatically stopped by ptrace.
             * Start tracing it.
             */
            if (new_pid != 0) {

                ptrace(
                    PTRACE_SYSCALL,
                    (pid_t)new_pid,
                    0,
                    0
                );
            }

            continue;
        }


        /*
         * Ignore non-syscall SIGTRAPs.
         */
        if (
            WSTOPSIG(status) !=
            (SIGTRAP | 0x80)
        )
        {
            ptrace(
                PTRACE_SYSCALL,
                current_pid,
                0,
                0
            );

            continue;
        }


        /*
         * Get registers.
         */
        if (
            ptrace(
                PTRACE_GETREGS,
                current_pid,
                0,
                &regs
            ) == -1
        )
        {
            perror("PTRACE_GETREGS");

            ptrace(
                PTRACE_SYSCALL,
                current_pid,
                0,
                0
            );

            continue;
        }


        /*
         * ENTER syscall.
         */
        if (traced[current].entering) {

            fprintf(
                syscall_file,
                "ENTER %s (%lld)\n",
                syscall_name(regs.orig_rax),
                (long long)regs.orig_rax
            );


            handle_file_syscall(
                current_pid,
                &regs,
                1
            );

            handle_process_syscall(
                current_pid,
                &regs,
                1
            );

            handle_memory_syscall(
                current_pid,
                &regs,
                1
            );

            handle_network_syscall(
                current_pid,
                &regs,
                1
            );

        }
        else {

            /*
             * EXIT syscall.
             */
            handle_file_syscall(
                current_pid,
                &regs,
                0
            );

            handle_process_syscall(
                current_pid,
                &regs,
                0
            );

            handle_memory_syscall(
                current_pid,
                &regs,
                0
            );

            handle_network_syscall(
                current_pid,
                &regs,
                0
            );


            if (
                regs.orig_rax == SYS_openat ||
                regs.orig_rax == SYS_open
            )
            {
                char *name =
                    search_fd((int)regs.rax);

                fprintf(
                    syscall_file,
                    "EXIT %s return=%lld",
                    syscall_name(regs.orig_rax),
                    (long long)regs.rax
                );

                if (name != NULL)
                    fprintf(
                        syscall_file,
                        " (%s)",
                        name
                    );

                fprintf(
                    syscall_file,
                    "\n"
                );
            }
            else {

                fprintf(
                    syscall_file,
                    "EXIT %s return=%lld\n",
                    syscall_name(regs.orig_rax),
                    (long long)regs.rax
                );
            }
        }


        fprintf(
            syscall_file,
            "----------------------------------\n"
        );


        /*
         * Toggle syscall enter/exit state.
         */
        traced[current].entering =
            !traced[current].entering;


        /*
         * Resume ONLY this process.
         */
        if (
            ptrace(
                PTRACE_SYSCALL,
                current_pid,
                0,
                0
            ) == -1
        )
        {
            /*
             * Process may have been killed by
             * the rule engine.
             */
            if (errno != ESRCH) {
                perror("PTRACE_SYSCALL");
            }
        }
    }


    close_alert();

    return root_pid;
}