#include "network_monitor.h"

#include <stdio.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/user.h>

#include "fd_tables.h"
#include "report.h"
#include "rules.h"
#include "event.h"
#include "alert.h"

void handle_network_syscall(pid_t pid,
                            struct user_regs_struct *regs,
                            int entering)
{
        char filename[256];
        event e;

char *name = NULL;   // initialize it
    if (entering) {

        switch (regs->orig_rax) {

        case SYS_socket:

            fprintf(syscall_file,"========== SOCKET ==========\n");
            fprintf(syscall_file,"Domain   : %lld\n", (long long)regs->rdi);
            fprintf(syscall_file,"Type     : %lld\n", (long long)regs->rsi);
            fprintf(syscall_file,"Protocol : %lld\n", (long long)regs->rdx);

            get_socket_entry();

            fprintf(syscall_file,"============================\n");
            report_network_section_socket((long long )regs->rdi,(long long )regs->rsi,(long long) regs->rdx);

            break;

        case SYS_connect:

            fprintf(syscall_file,"========== CONNECT ==========\n");

            fprintf(syscall_file,"Socket   : %lld", (long long)regs->rdi);

            name = search_fd(regs->rdi);
            if (name)
                fprintf(syscall_file," (%s)", name);

            fprintf(syscall_file,"\n");
            fprintf(syscall_file,"Address  : 0x%llx\n",
                   (unsigned long long)regs->rsi);
            fprintf(syscall_file,"Addr Len : %lld\n",
                   (long long)regs->rdx);

            fprintf(syscall_file,"=============================\n");
            report_network_section_connect((long long )regs->rdi,name, (long long)regs->rax);
            check_danger(pid,EVENT_NETWORK_CONNECT,"connect",name,0);
            break;

        case SYS_sendto:

            fprintf(syscall_file,"========== SENDTO ==========\n");

            fprintf(syscall_file,"Socket   : %lld", (long long)regs->rdi);

            name = search_fd(regs->rdi);
            if (name)
                fprintf(syscall_file," (%s)", name);

            fprintf(syscall_file,"\n");
            fprintf(syscall_file,"Buffer   : 0x%llx\n",
                   (unsigned long long)regs->rsi);
            fprintf(syscall_file,"Length   : %lld\n",
                   (long long)regs->rdx);
            fprintf(syscall_file,"Flags    : %lld\n",
                   (long long)regs->r10);
            fprintf(syscall_file,"Dest Addr: 0x%llx\n",
                   (unsigned long long)regs->r8);

            fprintf(syscall_file,"============================\n");
            report_network_section_send(regs->rdi, name, regs->rdx);
            break;

        case SYS_recvfrom:

            fprintf(syscall_file,"========== RECVFROM ==========\n");

            fprintf(syscall_file,"Socket   : %lld", (long long)regs->rdi);

            name = search_fd(regs->rdi);
            if (name)
                fprintf(syscall_file," (%s)", name);

            fprintf(syscall_file,"\n");
            fprintf(syscall_file,"Buffer   : 0x%llx\n",
                   (unsigned long long)regs->rsi);
            fprintf(syscall_file,"Length   : %lld\n",
                   (long long)regs->rdx);
            fprintf(syscall_file,"Flags    : %lld\n",
                   (long long)regs->r10);

            fprintf(syscall_file,"==============================\n");
            report_network_section_recv(regs->rdi, name, regs->rdx);
            break;

        case SYS_bind:

            fprintf(syscall_file,"========== BIND ==========\n");

            fprintf(syscall_file,"Socket   : %lld", (long long)regs->rdi);

            name = search_fd(regs->rdi);
            if (name)
                fprintf(syscall_file," (%s)", name);

            fprintf(syscall_file,"\n");
            fprintf(syscall_file,"Address  : 0x%llx\n",
                   (unsigned long long)regs->rsi);
            fprintf(syscall_file,"Addr Len : %lld\n",
                   (long long)regs->rdx);

            fprintf(syscall_file,"==========================\n");
            report_network_section_bind(regs->rdi, name, regs->rax);
            break;

        case SYS_listen:

            fprintf(syscall_file,"========== LISTEN ==========\n");

            fprintf(syscall_file,"Socket   : %lld", (long long)regs->rdi);

            name = search_fd(regs->rdi);
            if (name)
                fprintf(syscall_file," (%s)", name);

            fprintf(syscall_file,"\n");
            fprintf(syscall_file,"Backlog  : %lld\n",
                   (long long)regs->rsi);

            fprintf(syscall_file,"============================\n");
            report_network_section_listen(regs->rdi, name, regs->rax);
            break;

        case SYS_accept:

            fprintf(syscall_file,"========== ACCEPT ==========\n");

            fprintf(syscall_file,"Socket   : %lld", (long long)regs->rdi);

            name = search_fd(regs->rdi);
            if (name)
                fprintf(syscall_file," (%s)", name);

            fprintf(syscall_file,"\n");
            fprintf(syscall_file,"Address  : 0x%llx\n",
                   (unsigned long long)regs->rsi);
            fprintf(syscall_file,"Addr Len : %lld\n",
                   (long long)regs->rdx);

            fprintf(syscall_file,"============================\n");
            report_network_section_accept(regs->rdi, name, regs->rax);
            break;

        default:
            break;
        }

    } else {

        switch (regs->orig_rax) {

        case SYS_socket:

            fprintf(syscall_file,"========== SOCKET EXIT ==========\n");
            fprintf(syscall_file,"Return FD : %lld\n",
                   (long long)regs->rax);

            get_fd_exit(regs);

            fprintf(syscall_file,"=================================\n");
            report_network_section_socket(regs->rdi, regs->rsi, regs->rax);
                        report_network_section_socket((long long )regs->rdi,(long long )regs->rsi,(long long) regs->rdx);
    

            check_danger(pid,EVENT_NETWORK_SOCKET,"socket",filename,0);
            
            break;

        case SYS_connect:

            fprintf(syscall_file,"========== CONNECT EXIT ==========\n");
            fprintf(syscall_file,"Return : %lld\n",
                   (long long)regs->rax);
            fprintf(syscall_file,"==================================\n");
            report_network_section_connect(regs->rdi, name, regs->rax);
            check_danger(pid,EVENT_NETWORK_CONNECT,"connect",name,0);
            break;

        case SYS_sendto:

            fprintf(syscall_file,"========== SENDTO EXIT ==========\n");
            fprintf(syscall_file,"Bytes Sent : %lld\n",
                   (long long)regs->rax);
            fprintf(syscall_file,"=================================\n");
            report_network_section_send(regs->rdi, name, regs->rax);
            break;

        case SYS_recvfrom:

            fprintf(syscall_file,"========== RECVFROM EXIT ==========\n");
            fprintf(syscall_file,"Bytes Received : %lld\n",
                   (long long)regs->rax);
            fprintf(syscall_file,"===================================\n");
            report_network_section_recv(regs->rdi, name, regs->rax);
            break;

        case SYS_bind:

            fprintf(syscall_file,"========== BIND EXIT ==========\n");
            fprintf(syscall_file,"Return : %lld\n",
                   (long long)regs->rax);
            fprintf(syscall_file,"===============================\n");
            report_network_section_bind(regs->rdi, name, regs->rax);
            break;

        case SYS_listen:

            fprintf(syscall_file,"========== LISTEN EXIT ==========\n");
            fprintf(syscall_file,"Return : %lld\n",
                   (long long)regs->rax);
            fprintf(syscall_file,"=================================\n");
            report_network_section_listen(regs->rdi, name, regs->rax);
            break;

        case SYS_accept:

            fprintf(syscall_file,"========== ACCEPT EXIT ==========\n");
            fprintf(syscall_file,"New Socket : %lld\n",
                   (long long)regs->rax);
            fprintf(syscall_file,"=================================\n");
            report_network_section_accept(regs->rdi, name, regs->rax);
            break;

        default:
            break;
        }
    }
}