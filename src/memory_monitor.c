#include "memory_monitor.h"
#include <sys/syscall.h>
#include <stdio.h>
#include <sys/types.h>
#include "report.h"


void handle_memory_syscall(pid_t pid, struct user_regs_struct *regs, int entering){

switch(regs->orig_rax)
{
    case SYS_mmap:
    // Creates a new memory region.
        if (entering) {
            printf("==MMAP ENTER==\n");
            printf("Length : 0x%llx\n", (unsigned long long)regs->rsi);
            printf("Prot   : %lld\n", (long long)regs->rdx);
            printf("Flags  : %lld\n", (long long)regs->r10);
            printf("FD      : %lld\n", (long long)regs->r8);

        }else {

            printf("== MMAP EXIT ==\n");
            printf("Return : %lld\n", (long long)regs->rax);
            
        }
        break;
    
    case SYS_mprotect:
    // Changes permissions.
        if (entering) {
            printf("==MPROTECT ENTER==\n");
            printf("Addr : 0x%llx\n",(unsigned long long) regs->rdi);
            printf("Lenght : %lld\n",(long long)regs->rsi);
            printf("Protection : %lld\n",(long long)regs->rdx);

        }else{

            if ((long long)regs->rax==0){
            printf("== MPROTECT EXIT ==\n");
            printf("result : SUCCESS");
            }else{
            printf("== MPROTECT EXIT ==\n");
            printf("result : FAILED");
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
            printf("========== MUNMAP ENTER==========\n");
            printf("Addr : 0x%llx\n",(unsigned long long) regs->rdi);
            printf("Lenght : %lld\n",(long long)regs->rsi);
report_memory_section_munmap(
    pid,
    regs->rdi,
    regs->rsi,
    regs->rax
);
        }else{

            if ((long long)regs->rax==0){
            printf("========== MUNMAP EXIT===\n");
            printf("result : SUCCESS");
            
            }else{
            printf("== MUNMAP EXIT ==\n");
            printf("result : FAILED");
report_memory_section_munmap( pid,regs->rdi,regs->rsi,regs->rax);        
    }
        }
        break;

    case SYS_brk:
    // Changes the end of the data segment.
        if (entering) {
            printf("=== BRK ENTER==\n");
            printf("Addr : 0x%llx\n",(unsigned long long) regs->rdi);
            
        }else{

            if ((long long)regs->rax==0){
            printf("== BRK EXIT ==\n");
            printf("New program break : 0x%llx\n",(unsigned long long)regs->rax);
            }else{
            printf("== BRK EXIT ==\n");
            printf("result : FAILED\n");
            }
        }
        break;
    
    default:
        break;




}}