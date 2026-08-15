#include "process_monitor.h"

#include <stdio.h>
#include <sys/syscall.h>
#include "memory.h"
#include "alert.h"
#include "tracer.h"



// process_monitor.c trace process system calls (fork,execve...) for enrty and exit 
// and save the information in syscall.txt .
void handle_process_syscall(pid_t pid,
                            struct user_regs_struct *regs,
                           int entering)
{
 
char filename[256] = {0};

     switch (regs->orig_rax)
     {
     case SYS_execve:
     excve++;
       if (entering) {
        read_string(pid, regs->rdi, filename, sizeof(filename));
        write_alert("the process change his prog !");
        fprintf(syscall_file,"========== EXECVE ==========\n");
        fprintf(syscall_file,"Program : %s\n", filename);
        fprintf(syscall_file,"============================\n");
    }

    break;
     
     case SYS_fork:
      
        forkit++;
        fprintf(syscall_file,"[%d] FORK REQUESTED ====/n",pid);
        write_alert("the father create another process !");

     break;

     case SYS_wait4:

       process++;
       fprintf(syscall_file,"WAIT4 pid=%lld\n",regs->rdi);
       if (regs->rdi > 0)

    break;



     default:
        break;
     }


}