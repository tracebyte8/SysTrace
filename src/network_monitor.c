#include "network_monitor.h"

#include <stdio.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/user.h>

#include "fd_tables.h"
#include "report.h"

void handle_network_syscall(pid_t pid,
                            struct user_regs_struct *regs,
                            int entering)
{
char *name = NULL;   // initialize it
    if (entering) {

        switch (regs->orig_rax) {

        case SYS_socket:

            printf("========== SOCKET ==========\n");
            printf("Domain   : %lld\n", (long long)regs->rdi);
            printf("Type     : %lld\n", (long long)regs->rsi);
            printf("Protocol : %lld\n", (long long)regs->rdx);

            get_socket_entry();

            printf("============================\n");
            report_network_section_socket((long long )regs->rdi,(long long )regs->rsi,(long long) regs->rdx);
            break;

        case SYS_connect:

            printf("========== CONNECT ==========\n");

            printf("Socket   : %lld", (long long)regs->rdi);

            name = search_fd(regs->rdi);
            if (name)
                printf(" (%s)", name);

            printf("\n");
            printf("Address  : 0x%llx\n",
                   (unsigned long long)regs->rsi);
            printf("Addr Len : %lld\n",
                   (long long)regs->rdx);

            printf("=============================\n");
            report_network_section_connect((long long )regs->rdi,name, (long long)regs->rax);
            break;

        case SYS_sendto:

            printf("========== SENDTO ==========\n");

            printf("Socket   : %lld", (long long)regs->rdi);

            name = search_fd(regs->rdi);
            if (name)
                printf(" (%s)", name);

            printf("\n");
            printf("Buffer   : 0x%llx\n",
                   (unsigned long long)regs->rsi);
            printf("Length   : %lld\n",
                   (long long)regs->rdx);
            printf("Flags    : %lld\n",
                   (long long)regs->r10);
            printf("Dest Addr: 0x%llx\n",
                   (unsigned long long)regs->r8);

            printf("============================\n");
            report_network_section_send(regs->rdi, name, regs->rdx);
            break;

        case SYS_recvfrom:

            printf("========== RECVFROM ==========\n");

            printf("Socket   : %lld", (long long)regs->rdi);

            name = search_fd(regs->rdi);
            if (name)
                printf(" (%s)", name);

            printf("\n");
            printf("Buffer   : 0x%llx\n",
                   (unsigned long long)regs->rsi);
            printf("Length   : %lld\n",
                   (long long)regs->rdx);
            printf("Flags    : %lld\n",
                   (long long)regs->r10);

            printf("==============================\n");
            report_network_section_recv(regs->rdi, name, regs->rdx);
            break;

        case SYS_bind:

            printf("========== BIND ==========\n");

            printf("Socket   : %lld", (long long)regs->rdi);

            name = search_fd(regs->rdi);
            if (name)
                printf(" (%s)", name);

            printf("\n");
            printf("Address  : 0x%llx\n",
                   (unsigned long long)regs->rsi);
            printf("Addr Len : %lld\n",
                   (long long)regs->rdx);

            printf("==========================\n");
            report_network_section_bind(regs->rdi, name, regs->rax);
            break;

        case SYS_listen:

            printf("========== LISTEN ==========\n");

            printf("Socket   : %lld", (long long)regs->rdi);

            name = search_fd(regs->rdi);
            if (name)
                printf(" (%s)", name);

            printf("\n");
            printf("Backlog  : %lld\n",
                   (long long)regs->rsi);

            printf("============================\n");
            report_network_section_listen(regs->rdi, name, regs->rax);
            break;

        case SYS_accept:

            printf("========== ACCEPT ==========\n");

            printf("Socket   : %lld", (long long)regs->rdi);

            name = search_fd(regs->rdi);
            if (name)
                printf(" (%s)", name);

            printf("\n");
            printf("Address  : 0x%llx\n",
                   (unsigned long long)regs->rsi);
            printf("Addr Len : %lld\n",
                   (long long)regs->rdx);

            printf("============================\n");
            report_network_section_accept(regs->rdi, name, regs->rax);
            break;

        default:
            break;
        }

    } else {

        switch (regs->orig_rax) {

        case SYS_socket:

            printf("========== SOCKET EXIT ==========\n");
            printf("Return FD : %lld\n",
                   (long long)regs->rax);

            get_fd_exit(regs);

            printf("=================================\n");
            report_network_section_socket(regs->rdi, regs->rsi, regs->rax);
            break;

        case SYS_connect:

            printf("========== CONNECT EXIT ==========\n");
            printf("Return : %lld\n",
                   (long long)regs->rax);
            printf("==================================\n");
            report_network_section_connect(regs->rdi, name, regs->rax);
            break;

        case SYS_sendto:

            printf("========== SENDTO EXIT ==========\n");
            printf("Bytes Sent : %lld\n",
                   (long long)regs->rax);
            printf("=================================\n");
            report_network_section_send(regs->rdi, name, regs->rax);
            break;

        case SYS_recvfrom:

            printf("========== RECVFROM EXIT ==========\n");
            printf("Bytes Received : %lld\n",
                   (long long)regs->rax);
            printf("===================================\n");
            report_network_section_recv(regs->rdi, name, regs->rax);
            break;

        case SYS_bind:

            printf("========== BIND EXIT ==========\n");
            printf("Return : %lld\n",
                   (long long)regs->rax);
            printf("===============================\n");
            report_network_section_bind(regs->rdi, name, regs->rax);
            break;

        case SYS_listen:

            printf("========== LISTEN EXIT ==========\n");
            printf("Return : %lld\n",
                   (long long)regs->rax);
            printf("=================================\n");
            report_network_section_listen(regs->rdi, name, regs->rax);
            break;

        case SYS_accept:

            printf("========== ACCEPT EXIT ==========\n");
            printf("New Socket : %lld\n",
                   (long long)regs->rax);
            printf("=================================\n");
            report_network_section_accept(regs->rdi, name, regs->rax);
            break;

        default:
            break;
        }
    }
}