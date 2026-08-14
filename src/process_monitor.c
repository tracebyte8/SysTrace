#include "process_monitor.h"
#include "memory.h"
#include <sys/syscall.h>
#include "report.h"
#include "alert.h"

#include <stdio.h>
#include <sys/syscall.h>

void handle_process_syscall(pid_t pid,
                            struct user_regs_struct *regs,
                           int entering)
{
 
char filename[256] = {0};
     switch (regs->orig_rax)
     {
     case SYS_execve:

    if (entering) {
        read_string(pid, regs->rdi, filename, sizeof(filename));
        write_alert("the process change his prog !");
        fprintf(syscall_file,"========== EXECVE ==========\n");
        fprintf(syscall_file,"Program : %s\n", filename);
        fprintf(syscall_file,"============================\n");
        report_process_section_exec(filename);
    }

    break;
     
     case SYS_fork:
      
        fprintf(syscall_file,"[%d] FORK REQUESTED ====/n",pid);
        write_alert("the father create another process !");
        report_process_section_fork(pid);

     break;

     case SYS_wait4:

       fprintf(syscall_file,"WAIT4 pid=%lld\n",regs->rdi);
       if (regs->rdi > 0)
    report_process_section_wait(regs->rdi);

    break;



     default:
        break;
     }


}