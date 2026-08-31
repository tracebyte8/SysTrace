#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

int main(void)
{
    printf("[TEST] Starting SysTrace test\n");

    /* =========================
     * OPEN + READ + CLOSE
     * ========================= */
    printf("[TEST] Opening /etc/hostname\n");

    int fd = open("/etc/hostname", O_RDONLY);

    if (fd >= 0) {
        char buffer[128];

        ssize_t n = read(fd, buffer, sizeof(buffer) - 1);

        if (n > 0) {
            buffer[n] = '\0';
            printf("[TEST] Read: %s\n", buffer);
        }

        close(fd);
    }

    /* =========================
     * MPROTECT
     * ========================= */
    printf("[TEST] mmap + mprotect\n");

    void *mem = mmap(
        NULL,
        4096,
        PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );

    if (mem != MAP_FAILED) {

        if (mprotect(mem, 4096, PROT_READ | PROT_EXEC) == 0)
            printf("[TEST] mprotect RW -> RX succeeded\n");

        munmap(mem, 4096);
    }

    /* =========================
     * PTRACE
     * ========================= */
    printf("[TEST] ptrace\n");

    long ret = ptrace(PTRACE_TRACEME, 0, NULL, NULL);

    if (ret == 0)
        printf("[TEST] ptrace succeeded\n");
    else
        perror("[TEST] ptrace");

    /* =========================
     * FORK
     * ========================= */
    printf("[TEST] Creating children\n");

    for (int i = 0; i < 3; i++) {

        pid_t pid = fork();

        if (pid < 0) {
            perror("fork");
            break;
        }

        if (pid == 0) {

            printf("[CHILD] PID: %d\n", getpid());

            int child_fd = open(
                "/tmp/systrace-test.txt",
                O_WRONLY | O_CREAT | O_APPEND,
                0644
            );

            if (child_fd >= 0) {

                const char *msg = "SysTrace test\n";

                write(child_fd, msg, 14);

                close(child_fd);
            }

            _exit(0);
        }
    }

    /* Parent waits for children */
    while (wait(NULL) > 0)
        ;

    /* =========================
     * EXEC
     * ========================= */
    printf("[TEST] Executing /bin/true\n");

    char *args[] = {
        "true",
        NULL
    };

    execv("/bin/true", args);

    perror("[TEST] execv");

    return 0;
}