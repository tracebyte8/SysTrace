#include "process_monitor.h"

#include <stdio.h>
#include <sys/syscall.h>

#include "memory.h"
#include "alert.h"
#include "tracer.h"
#include "stat.h"
#include "rules.h"

void handle_process_syscall(
    pid_t pid,
    struct user_regs_struct *regs,
    int entering
)
{
    char filename[256] = {0};

    syscall_stat *stats = get_stats(pid);

    if (stats == NULL)
        return;

    switch (regs->orig_rax)
    {
    case SYS_execve:

        if (entering) {

            read_string(
                pid,
                regs->rdi,
                filename,
                sizeof(filename)
            );

            stats->execve++;
            stats->process++;

            check_danger(
                pid,
                EVENT_PROCESS_EXEC,
                "execve",
                filename,
                0
            );

            fprintf(
                syscall_file,
                "========== EXECVE ==========\n"
                "Program : %s\n"
                "============================\n",
                filename
            );
        }

        break;


    case SYS_fork:

        if (entering) {

            stats->fork++;
            stats->process++;

            fprintf(
                syscall_file,
                "[%d] FORK REQUESTED\n",
                pid
            );

            check_danger(
                pid,
                EVENT_PROCESS_FORK,
                "fork",
                filename,
                0
            );
        }

        break;


    case SYS_wait4:

        if (!entering) {

            stats->process++;

            fprintf(
                syscall_file,
                "WAIT4 pid=%lld\n",
                (long long)regs->rdi
            );
        }

        break;


    case SYS_clone:

        if (entering) {

            stats->fork++;
            stats->process++;

            fprintf(
                syscall_file,
                "[%d] CLONE REQUESTED\n",
                pid
            );

            check_danger(
                pid,
                EVENT_PROCESS_FORK,
                "clone",
                filename,
                0
            );
        }

        break;


    case SYS_ptrace:

        if (entering) {

            fprintf(
                syscall_file,
                "PTRACE request=%lld\n",
                (long long)regs->rdi
            );

            stats->ptrace++;
            stats->process++;

            write_alert(
                "some process wants to trace another process!"
            );

            check_danger(
                pid,
                EVENT_PRCOESS_PTRACE,
                "ptrace",
                " ",
                0
            );
        }

        break;


    default:
        break;
    }
}