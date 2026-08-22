#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

#define STACK_SIZE (1024 * 1024)



/* 
 *
 * clone() arguments:
 *
 * 1. child_function
 *    The function where the new child starts executing.
 *
 * 2. stack_top
 *    Memory that the child uses as its stack.
 *    This stack is NOT the namespace.
 *
 * 3. CLONE_NEWPID | SIGCHLD
 *    CLONE_NEWPID:
 *        Create a new PID namespace for the child.
 *
 *    SIGCHLD:
 *        Notify the parent when the child terminates.
 *
 * 4. target_argv
 *    Data passed to child_function().
 *
 *
 * The child starts in child_function().
 * At this point it is already inside the new PID namespace.
 *
 * execvp() then replaces the child process with the target
 * program. The target therefore runs inside the namespace.
 *
 * The parent receives the child's PID from clone() and waits
 * for the target to terminate using waitpid().
 */

static int child_function(void *arg)
{
    char **target_argv = arg;

    printf("Child PID inside namespace: %d\n", getpid());
    
        if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        perror("mount");
        return 1;
    }

    execvp(target_argv[0], target_argv);

    perror("execvp");

    return 1;
}


int create_namespace(char **target_argv)
{

    char *stack = malloc(STACK_SIZE);

    if (!stack) {
        perror("malloc");
        return 1;
    }

    char *stack_top = stack + STACK_SIZE;

    pid_t pid = clone(
           child_function,
           stack_top,
           CLONE_NEWPID | CLONE_NEWNS |SIGCHLD,
           target_argv
    );

    if (pid == -1) {
        perror("clone");
        free(stack);
        return 1;
    }

    printf("Host sees child as PID %d\n", pid);

    if (waitpid(pid, NULL, 0) == -1) {
        perror("waitpid");
        free(stack);
        return 1;
    }

    free(stack);

    return 0;
}