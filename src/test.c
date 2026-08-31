// Simulates a fork-bomb-like pattern WITHOUT actually bombing the system.
// Real fork bombs recurse unbounded; here we hard-cap total children
// and always wait() them, so it's safe to run repeatedly.
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>

#define MAX_CHILDREN 15

int main(void)
{
    for (int i = 0; i < MAX_CHILDREN; i++) {
        pid_t pid = fork();

        if (pid == 0) {
            // Child: do nothing meaningful, exit immediately
            _exit(0);
        } else if (pid > 0) {
            waitpid(pid, NULL, 0); // reap before spawning the next one
        } else {
            perror("fork");
        }
    }

    printf("mal_forkbomb: done (%d children spawned, all reaped)\n", MAX_CHILDREN);
    return 0;
}
