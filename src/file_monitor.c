#include "file_monitor.h"
#include "memory.h"
#include <sys/syscall.h>
#include "report.h"

#include <stdio.h>
#include <sys/syscall.h>

#include "fd_tables.h"

void handle_file_syscall(pid_t pid,
                         struct user_regs_struct *regs,
                         int entering)
{
    char filename[257];

    switch (regs->orig_rax)
    {
        case SYS_openat:

            if (entering)
            {
                read_string(pid, regs->rsi, filename, sizeof(filename));
                get_file_entry(pid, regs, filename);

                printf("OPEN : %s\n", filename);
                printf("dirfd = %lld | flags = %lld\n",
                       regs->rdi,
                       regs->rdx);
                
                report_file_section_open(filename, regs->rdi, regs->rdx);
            }
            else
            {
                get_fd_exit(regs);
            }

            break;

        case SYS_read:

            if (entering)
            {
                char *path = search_fd(regs->rdi);

                printf("READ fd=%lld", regs->rdi);

                if (path)
                    printf(" (%s)", path);

                printf(" | bytes=%lld\n", regs->rdx);
                report_file_section_read(regs->rdi, path, regs->rdx);
            }

            break;

        case SYS_close:

            if (entering)
            {
                char *path = search_fd(regs->rdi);

                printf("CLOSE fd=%lld", regs->rdi);

                if (path)
                    printf(" (%s)", path);

                printf("\n");
                report_file_section_close(regs->rdi, path);
            }
            else
            {
                remove_fd(regs->rdi);
            }

            break;

        default:
            break;
    }
}