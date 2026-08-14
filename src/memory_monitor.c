#include "memory_monitor.h"
#include <sys/syscall.h>
#include <stdio.h>
#include <sys/types.h>
#include "report.h"
#include "rules.h"
#include "alert.h"


void handle_memory_syscall(pid_t pid, struct user_regs_struct *regs, int entering){

switch(regs->orig_rax)
{
    case SYS_mmap:
    // Creates a new memory region.
        if (entering) {
            fprintf(syscall_file,"==MMAP ENTER==\n");
            fprintf(syscall_file,"Length : 0x%llx\n", (unsigned long long)regs->rsi);
            fprintf(syscall_file,"Prot   : %lld\n", (long long)regs->rdx);
            fprintf(syscall_file,"Flags  : %lld\n", (long long)regs->r10);
            fprintf(syscall_file,"FD      : %lld\n", (long long)regs->r8);

        }else {

            fprintf(syscall_file,"== MMAP EXIT ==\n");
            fprintf(syscall_file,"Return : %lld\n", (long long)regs->rax);
            
        }
        break;
    
    case SYS_mprotect:
    // Changes permissions.
        if (entering) {
            fprintf(syscall_file,"==MPROTECT ENTER==\n");
            fprintf(syscall_file,"Addr : 0x%llx\n",(unsigned long long) regs->rdi);
            fprintf(syscall_file,"Lenght : %lld\n",(long long)regs->rsi);
            fprintf(syscall_file,"Protection : %lld\n",(long long)regs->rdx);

        }else{

            if ((long long)regs->rax==0){
            fprintf(syscall_file,"== MPROTECT EXIT ==\n");
            fprintf(syscall_file,"result : SUCCESS");
            }else{
            fprintf(syscall_file,"== MPROTECT EXIT ==\n");
            fprintf(syscall_file,"result : FAILED");
            }  
report_memory_section_mprotect(
    pid,
    regs->rdi,   // addr
    regs->rsi,   // length
    regs->rdx,   // prot
    regs->rax    // return value
);        }
        break;
    
    case SYS_munmap:
    // Removes a memory region.
        if (entering) {
            fprintf(syscall_file,"========== MUNMAP ENTER==========\n");
            fprintf(syscall_file,"Addr : 0x%llx\n",(unsigned long long) regs->rdi);
            fprintf(syscall_file,"Lenght : %lld\n",(long long)regs->rsi);
report_memory_section_munmap(
    pid,
    regs->rdi,
    regs->rsi,
    regs->rax
);
        }else{

            if ((long long)regs->rax==0){
            fprintf(syscall_file,"========== MUNMAP EXIT===\n");
            fprintf(syscall_file,"result : SUCCESS");
            
            }else{
            fprintf(syscall_file,"== MUNMAP EXIT ==\n");
            fprintf(syscall_file,"result : FAILED");
report_memory_section_munmap( pid,regs->rdi,regs->rsi,regs->rax);        
    }
        }
        break;

    case SYS_brk:
    // Changes the end of the data segment.
        if (entering) {
            fprintf(syscall_file,"=== BRK ENTER==\n");
            fprintf(syscall_file,"Addr : 0x%llx\n",(unsigned long long) regs->rdi);
            
        }else{

            if ((long long)regs->rax==0){
            fprintf(syscall_file,"== BRK EXIT ==\n");
            fprintf(syscall_file,"New program break : 0x%llx\n",(unsigned long long)regs->rax);
            }else{
            fprintf(syscall_file,"== BRK EXIT ==\n");
            fprintf(syscall_file,"result : FAILED\n");
            }
        }
        break;
    
    default:
        break;




}}