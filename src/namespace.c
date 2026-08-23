
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
  

    /*
     * Allow the parent tracer to trace this process.
     */
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        perror("PTRACE_TRACEME");
        return 1;
    }

    /*
     * Stop here so the parent can set ptrace options
     * before sandbox setup begins.
     */
    raise(SIGSTOP);

    printf("Child PID inside namespace: %d\n", getpid());

    /*
     * 1. Make the mount tree private.
     *
     * Mount and unmount operations inside this namespace
     * will not propagate to the host mount namespace.
     */
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        perror("mount MS_PRIVATE");
        return 1;
    }

    /*
     * 2. Make the sandbox root a mount point.
     *
     * This bind mount does not copy files. It prepares
     * /tmp/systrace-root to become the new root filesystem.
     */
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

    /*
     * 3. Enter the directory that will become the new root.
     */
    if (chdir("/tmp/systrace-root") == -1) {
        perror("chdir systrace-root");
        return 1;
    }

    /*
     * 4. Replace the current root with systrace-root.
     *
     * "."         is the new root.
     * "./oldroot" temporarily contains the old root.
     */
    if (syscall(SYS_pivot_root, ".", "./oldroot") == -1) {
        perror("pivot_root");
        return 1;
    }

    /*
     * 5. Move the working directory to the new root.
     */
    if (chdir("/") == -1) {
        perror("chdir /");
        return 1;
    }

    /*
     * 6. Remove the old host root from the sandbox.
     */
    if (umount2("/oldroot", MNT_DETACH) == -1) {
        perror("umount /oldroot");
        return 1;
    }

    /*
     * 7. Create /tmp before mounting tmpfs.
     */
    if (mkdir("/tmp", 0755) == -1 && errno != EEXIST) {
        perror("mkdir /tmp");
        return 1;
    }

    /*
     * 8. Mount a private temporary filesystem at /tmp.
     */
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

    /*
     * 9. Execute the target inside the sandbox.
     *
     * target_argv[0] must exist inside the new root.
     */
    execvp(target_argv[0], target_argv);

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

    /*
     * Create a child with separate PID and mount namespaces.
     */
pid_t pid = clone(
    child_function,
    stack_top,
CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | SIGCHLD,    target_argv
);

    if (pid == -1) {
        perror("clone");
        free(stack);
        return (pid_t)-1;
    }

    printf("Host sees child as PID %d\n", pid);

    /*
     * Return the sandbox child PID to the tracer.
     * The tracer is responsible for waitpid() and ptrace().
     */
    return pid;
}
