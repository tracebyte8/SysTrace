#include "file_monitor.h"

#include "memory.h"
#include <sys/syscall.h>
#include "tracer.h"
#include "alert.h"
#include "event.h"
#include <stdio.h>
#include <sys/syscall.h>
#include <string.h>
#include "rules.h"
#include "fd_tables.h"
#include "dataset.h"
#include "stat.h"

void handle_file_syscall(pid_t pid,
                         struct user_regs_struct *regs,
                         int entering)
{
    event e;
    char filename[256];
    syscall_stat *stats = get_stats(pid);

    switch (regs->orig_rax)
    {
        case SYS_openat:

            if (entering)
            {
                stats->open++;
                stats->file++;

                read_string(pid, regs->rsi, filename, sizeof(filename));
                get_file_entry(pid, regs, filename);

                fprintf(syscall_file, "OPEN : %s\n", filename);

                if (strcmp("/etc/passwd", filename) == 0) {
                    write_alert("[ALERT] the process try to open /etc/passwd");
                }

                fprintf(syscall_file, "dirfd = %lld | flags = %lld\n",
                        regs->rdi,
                        regs->rdx);

                check_danger(pid, EVENT_FILE_OPEN, "open", filename, 0);
            }
            else
            {
                stats->open++;
                stats->file++;
                check_danger(pid, EVENT_FILE_OPEN, "open", filename, 0);
                get_fd_exit(regs);
            }

            break;
            case SYS_open:

    if (entering)
    {
        stats->open++;
        stats->file++;

        read_string(pid, regs->rdi, filename, sizeof(filename));  // note: rdi, not rsi
        get_file_entry(pid, regs, filename);

        fprintf(syscall_file, "OPEN : %s\n", filename);

        if (strcmp("/etc/passwd", filename) == 0) {
            write_alert("[ALERT] the process try to open /etc/passwd");
        }

        check_danger(pid, EVENT_FILE_OPEN, "open", filename, 0);
    }
    else
    {
        stats->open++;
        stats->file++;
        check_danger(pid, EVENT_FILE_OPEN, "open", filename, 0);
        get_fd_exit(regs);
    }

    break;

        case SYS_read:

            if (entering)
            {
                stats->read++;
                stats->file++;

                char *path = search_fd(regs->rdi);

                fprintf(syscall_file, "READ fd=%lld", regs->rdi);

                if (path) {
                    fprintf(syscall_file, " (%s)", path);

                    if (strcmp("/etc/passwd", path) == 0) {
                        write_alert("[ALERT] the process try to read from /etc/passwd");
                    }
                }

                fprintf(syscall_file, " | bytes=%lld\n", regs->rdx);

                strcpy(e.syscall, "read");

                check_danger(pid, EVENT_FILE_READ, "read", filename, 0);
            }

            break;

        case SYS_close:

            if (entering)
            {
                stats->close++;
                stats->file++;

                char *path = search_fd(regs->rdi);

                fprintf(syscall_file, "CLOSE fd=%lld", regs->rdi);

                if (path) {
                    fprintf(syscall_file, " (%s)", path);

                    if (strcmp("/etc/passwd", path) == 0) {
                        write_alert("[ALERT] the process try to close /etc/passwd");
                    }
                }

                fprintf(syscall_file, "\n");
            }
            else
            {
                stats->close++;
                stats->file++;
                remove_fd(regs->rdi);
            }

            break;

        default:
            break;
    }
}