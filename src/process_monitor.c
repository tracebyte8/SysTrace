#include "process_monitor.h"

#include <stdio.h>
#include <sys/syscall.h>
#include "memory.h"
#include "alert.h"
#include "tracer.h"
#include "stat.h"
#include "rules.h"

void handle_process_syscall(pid_t pid,
                            struct user_regs_struct *regs,
                            int entering)
{
    char filename[256] = {0};
    syscall_stat *stats = get_stats(pid);

    switch (regs->orig_rax)
    {
    case SYS_execve:

        if (entering) {
            read_string(pid, regs->rdi, filename, sizeof(filename));
            fprintf(syscall_file,"========== EXECVE ==========\n");
            fprintf(syscall_file,"Program : %s\n", filename);
            fprintf(syscall_file,"============================\n");
        }else{
            

          stats->execve++;
          stats->process++;

            read_string(pid, regs->rdi, filename, sizeof(filename));
            write_alert("the process change his prog !");
            fprintf(syscall_file,"========== EXECVE ==========\n");
            fprintf(syscall_file,"Program : %s\n", filename);
            fprintf(syscall_file,"============================\n");
        }

        break;

    case SYS_fork:

   
        if (entering){

        fprintf(syscall_file,"[%d] FORK REQUESTED ====/n",pid);
        write_alert("the father create another process !");
        check_danger(pid, EVENT_PROCESS_FORK, "fork", filename, 0);

        }else{
                  stats->fork++;
                  stats->process++; 
        }
        break;

    case SYS_wait4:
        if(!entering){
        stats->process++;
        fprintf(syscall_file,"WAIT4 pid=%lld\n",regs->rdi);

        if (regs->rdi > 0)
            break;

        }break;

    case SYS_clone:

 
if (entering){
        fprintf(syscall_file,"clone pid=%lld\n",regs->rdi);
        write_alert("the father create another process !");
        check_danger(pid, EVENT_PROCESS_FORK, "clone", filename, 0);
    }else{
              stats->fork++;
        stats->process++; 

    }
        break;

    case SYS_ptrace :

    fprintf(syscall_file,"PTRACE pid=%lld\n",regs->rdi);
    write_alert("some process want to trace another one !");
        check_danger(pid,EVENT_PRCOESS_PTRACE, "ptrace", filename, 0);
        stats->ptrace++;
                stats->process++; 



    default:
        break;
    }
}