#define _GNU_SOURCE

#include "isolate.h"
#include "set_root.h"

#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#define STACK_SIZE (1024 * 1024)

static int child_function(void *arg)
{
    char **target_argv = arg;

    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        perror("PTRACE_TRACEME");
        return 1;
    }

    raise(SIGSTOP);

    printf("Child PID inside namespace: %d\n", getpid());

    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        perror("mount MS_PRIVATE");
        return 1;
    }

    if (mount(
            "/tmp/systrace-root",
            "/tmp/systrace-root",
            NULL,
            MS_BIND | MS_REC,
            NULL
        ) == -1) {
        perror("bind mount systrace-root");
        return 1;
    }

    if (chdir("/tmp/systrace-root") == -1) {
        perror("chdir systrace-root");
        return 1;
    }

    if (syscall(SYS_pivot_root, ".", "./oldroot") == -1) {
        perror("pivot_root");
        return 1;
    }

    if (chdir("/") == -1) {
        perror("chdir /");
        return 1;
    }

    if (umount2("/oldroot", MNT_DETACH) == -1) {
        perror("umount /oldroot");
        return 1;
    }

    if (mkdir("/tmp", 0755) == -1 && errno != EEXIST) {
        perror("mkdir /tmp");
        return 1;
    }

    if (mount(
            "tmpfs",
            "/tmp",
            "tmpfs",
            0,
            NULL
        ) == -1) {
        perror("mount tmpfs /tmp");
        return 1;
    }

char *argv[] = {
    "/basic_target",
    NULL
};

execv("/basic_target", argv);
    perror("execvp");
    return 1;
}

pid_t create_namespace(char **target_argv)
{
    if (set_up_root(target_argv[0]) == -1) {
        fprintf(stderr, "failed to setup root filesystem\n");
        return (pid_t)-1;
    }

    char *stack = malloc(STACK_SIZE);

    if (stack == NULL) {
        perror("malloc");
        return (pid_t)-1;
    }

    char *stack_top = stack + STACK_SIZE;

    pid_t pid = clone(
        child_function,
        stack_top,
         CLONE_NEWUSER| CLONE_NEWPID | CLONE_NEWNS | SIGCHLD,
        target_argv
    );

    if (pid == -1) {
        perror("clone");
        free(stack);
        return (pid_t)-1;
    }

    printf("Host sees child as PID %d\n", pid);

    return pid;
}