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

void set_trace_options(pid_t pid)
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
}
}


void trace(char *program)

{

    pid_t pid = fork();
    int status;

    if (pid == -1) {
        perror("fork");
        return;
    }

   struct traced_process traced[128];
     int traced_count = 1;
     traced[0].pid = pid;
     traced[0].entering = 1;
     traced[0].parent = 0;

    
    if (pid == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(program, program, NULL);
        printf("EXECUTING %s\n", program);
        fflush(stdout);
        perror("execl");
        _exit(1);
    }

    waitpid(pid, &status, 0);

    // If this stop is specifically because of a system call trap, alter the signal number slightly so I know.
    
    set_trace_options(pid);


    struct user_regs_struct regs;

    // tracing Loop until the child process exits
    
    while (1) {


    for (int i = 0; i < traced_count; i++)
    {
        ptrace(PTRACE_SYSCALL, traced[i].pid, 0, 0);}

        // search for who stopped and will get traced 
        pid_t current_pid = waitpid(-1, &status, 0);
        
    
       if (current_pid == -1)
         break;


        // search for the current_pid in the traced array to find the index of the process that stopped ,
        // if not found, continue to the next iteration of the loop
        // to use entring and exiting 
        
        int current = -1;


        for (int i = 0; i < traced_count; i++) {
             if (traced[i].pid == current_pid) {
                 current = i;
             break;
             }
      }

        printf("PID=%d PPID=%d STATUS=0x%x EVENT=%u SIG=%d\n",
              current_pid,
              traced[current].parent,
               status,
               status >> 16,
               WSTOPSIG(status));
    
        // if this pid not in array of traced process, continue to the next iteration of the loop
       
        if (current == -1)
            continue;

         // if the process exited, remove it from the traced array and continue to the next iteration of the loop
    
         if (WIFEXITED(status)) {

           remove_process(traced,
                          &traced_count,
                         current);

           if (traced_count == 0)
                break;

    continue;
   }

       // if the process is not stopped, continue to the next iteration of the loop
       // If the process is not stopped, ignore it.

       if (!WIFSTOPPED(status))
           continue;

// Check whether this stop is a ptrace event.
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

        printf("Parent %d -> Child %lu\n",
              current_pid,
               new_pid);
    
                traced[traced_count].pid = new_pid;
                traced[traced_count].entering = 1;
                traced[traced_count].parent = current_pid; 
                traced_count++;

               set_trace_options(new_pid);
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
            
            printf("ENTER %s (%lld)\n", syscall_name(regs.orig_rax), (long long)regs.orig_rax);

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

                printf("EXIT  %s return=%lld",
                       syscall_name(regs.orig_rax),
                       (long long)regs.rax);

                if (name != NULL)
                    printf(" (%s)", name);

                printf("\n");

            } else {

                printf("EXIT  %s return=%lld\n",
                       syscall_name(regs.orig_rax),
                       (long long)regs.rax);
            }
        }

        printf("----------------------------------\n");

        traced[current].entering = !traced[current].entering;
    }
}