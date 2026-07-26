#include "fd_tables.h"

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/user.h>

#include "memory.h"

struct fd_info {
    char name[100];
    int fd;
};

static struct fd_info table[100];
static int count = 0;

/* Store a file before openat() returns */


void get_file_entry(pid_t pid,
                    struct user_regs_struct *regs,
                    char filename[100])
{
    read_string(pid, regs->rsi, filename, sizeof(table[count].name));
    strcpy(table[count].name, filename);
}


/* Store a socket before socket() returns */


void get_socket_entry(void)
{
    strcpy(table[count].name, "socket");
}


/* Common exit function for both openat() and socket() */


void get_fd_exit(struct user_regs_struct *regs)
{
    if ((long long)regs->rax >= 0) {
        table[count].fd = (int)regs->rax;
        count++;
    }
}


/* Search */


char *search_fd(int fd)
{
    for (int j = 0; j < count; j++) {
        if (table[j].fd == fd)
            return table[j].name;
    }

    return NULL;
}


/* Remove */


void remove_fd(int fd)
{
    for (int j = 0; j < count; j++) {

        if (table[j].fd == fd) {

            for (int k = j; k < count - 1; k++)
                table[k] = table[k + 1];

            count--;
            break;
        }
    }
}