#include "file_monitor.h"
#include "memory.h"
#include <sys/syscall.h>
#include "report.h"
#include "alert.h"
#include "event.h"

#include <stdio.h>
#include <sys/syscall.h>
#include <string.h>
#include "rules.h"



#include "fd_tables.h"

void handle_file_syscall(pid_t pid,
                         struct user_regs_struct *regs,
                         int entering)
{
    event e;
    char filename[256];

    switch (regs->orig_rax)
    {
        case SYS_openat:

            if (entering)
            {
                // read  regs->rsi and save it in file name
                read_string(pid, regs->rsi, filename, sizeof(filename));
                get_file_entry(pid, regs, filename);
           
                printf("OPEN : %s\n", filename);

                if  (strcmp("/etc/passwd",filename)==0){
                    write_alert("[ALERT] the process try to open /etc/passwd");
                }
                
                printf("dirfd = %lld | flags = %lld\n",
                       regs->rdi,
                       regs->rdx);
                report_file_section_open(filename, regs->rdi, regs->rdx);

                e.type =EVENT_FILE_OPEN;
                strcpy(e.syscall, "open");
                strncpy(e.path, filename, sizeof(e.path) - 1);
                e.path[sizeof(e.path) - 1] = '\0';
                e.pid=pid;
                check_rules(&e);
            }
            else
            {
                                strcpy(e.syscall, "open");

                 e.type =EVENT_FILE_OPEN;
                strncpy(e.path, filename, sizeof(e.path) - 1);
                e.path[sizeof(e.path) - 1] = '\0';
                e.pid=pid;
                check_rules(&e);
                get_fd_exit(regs);
            }

            break;

        case SYS_read:

            if (entering)
            {

                char *path = search_fd(regs->rdi);

                printf("READ fd=%lld", regs->rdi);

                if (path){
                    printf(" (%s)", path);
                  if  (strcmp("/etc/passwd",path)==0){
                    write_alert("[ALERT] the process try to read from /etc/passwd");
                }
                }
                    

                printf(" | bytes=%lld\n", regs->rdx);
                strcpy(e.syscall,"read");
                report_file_section_read(regs->rdi, path, regs->rdx);
                 e.type =EVENT_FILE_READ;
                strncpy(e.path, path, sizeof(e.path) - 1);
                e.path[sizeof(e.path) - 1] = '\0';
                e.pid=pid;
                check_rules(&e);
            }

            break;

        case SYS_close:

            if (entering)
            {
                char *path = search_fd(regs->rdi);

                printf("CLOSE fd=%lld", regs->rdi);


                if (path){
                    printf(" (%s)", path);
                  if  (strcmp("/etc/passwd",path)==0){
                    write_alert("[ALERT] the process try to close /etc/passwd");
                }
                }
                    

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