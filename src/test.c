/*
 * rule_test.c
 *
 * Deterministic, self-contained test harness for exercising a
 * ptrace-based syscall monitor / rule engine.
 *
 * This program is intentionally benign:
 *   - all file I/O happens on a temp file created by the program itself
 *   - the only network activity is a single connect() attempt to
 *     127.0.0.1 on a high port that is expected to fail (no listener)
 *   - only /bin/echo (or /bin/true as fallback) is executed
 *   - at most 2 child processes are ever created
 *   - no shell is invoked, no persistence, no external addresses
 *
 * Build:
 *   gcc -Wall -Wextra -O0 rule_test.c -o rule_test
 *
 * Run:
 *   ./rule_test
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define TEST_FILE_TEMPLATE "/tmp/rule_test_XXXXXX"
#define TEST_PORT          54137   /* high, unlikely to be in use */

/* ---------------------------------------------------------------- */
/* [PTRACe] self-trace so the harness process is directly visible
 * to a ptrace-attached monitor from the moment it starts.
 */
static void step_ptrace_self(void)
{
    printf("[PTRACe] requesting PTRACE_TRACEME\n");

    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        /* Not fatal: if a tracer is already attached this can fail. */
        perror("[PTRACe] PTRACE_TRACEME");
    } else {
        printf("[PTRACe] traceme OK\n");
    }
}

/* ---------------------------------------------------------------- */
/* [OPEN/READ/CLOSE] create a temp file, write a few bytes with the
 * parent, then open/read/close it explicitly so those syscalls are
 * clearly attributable.
 */
static int step_open_read_close(char *path_out, size_t path_out_len)
{
    char path[] = TEST_FILE_TEMPLATE;
    int fd = mkstemp(path);

    if (fd == -1) {
        perror("[OPEN/READ/CLOSE] mkstemp");
        return -1;
    }

    const char *payload = "rule_test harness payload\n";
    ssize_t written = write(fd, payload, strlen(payload));
    if (written == -1) {
        perror("[OPEN/READ/CLOSE] write");
    }
    close(fd);

    printf("[OPEN/READ/CLOSE] created temp file %s\n", path);

    /* Reopen explicitly via openat(AT_FDCWD, ...) semantics. */
    int reopened = openat(AT_FDCWD, path, O_RDONLY);
    if (reopened == -1) {
        perror("[OPEN/READ/CLOSE] openat");
        return -1;
    }
    printf("[OPEN/READ/CLOSE] openat OK fd=%d\n", reopened);

    char buf[128];
    ssize_t n = read(reopened, buf, sizeof(buf) - 1);
    if (n == -1) {
        perror("[OPEN/READ/CLOSE] read");
    } else {
        buf[n] = '\0';
        printf("[OPEN/READ/CLOSE] read %zd bytes: %s", n, buf);
    }

    if (close(reopened) == -1)
        perror("[OPEN/READ/CLOSE] close");
    else
        printf("[OPEN/READ/CLOSE] close OK\n");

    strncpy(path_out, path, path_out_len - 1);
    path_out[path_out_len - 1] = '\0';
    return 0;
}

/* ---------------------------------------------------------------- */
/* [CHMOD] flip permissions on the temp file the test created. */
static void step_chmod(const char *path)
{
    printf("[CHMOD] chmod 0600 on %s\n", path);
    if (chmod(path, 0600) == -1)
        perror("[CHMOD] chmod");
    else
        printf("[CHMOD] chmod OK\n");
}

/* ---------------------------------------------------------------- */
/* [MMAP/MPROTECT] anonymous mapping, write to it, then tighten
 * protection flags before unmapping.
 */
static void step_mmap_mprotect(void)
{
    size_t len = 4096;

    printf("[MMAP/MPROTECT] mmap %zu bytes anonymous\n", len);

    void *mem = mmap(NULL, len, PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mem == MAP_FAILED) {
        perror("[MMAP/MPROTECT] mmap");
        return;
    }

    memset(mem, 0x41, len);
    printf("[MMAP/MPROTECT] mmap OK at %p, wrote pattern\n", mem);

    if (mprotect(mem, len, PROT_READ) == -1) {
        perror("[MMAP/MPROTECT] mprotect");
    } else {
        printf("[MMAP/MPROTECT] mprotect(PROT_READ) OK\n");
    }

    if (munmap(mem, len) == -1)
        perror("[MMAP/MPROTECT] munmap");
    else
        printf("[MMAP/MPROTECT] munmap OK\n");
}

/* ---------------------------------------------------------------- */
/* [SOCKET/CONNECT] localhost-only connect attempt on a high port
 * with no listener expected; failure is treated as a normal result.
 */
static void step_socket_connect(void)
{
    printf("[SOCKET/CONNECT] socket(AF_INET, SOCK_STREAM)\n");

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) {
        perror("[SOCKET/CONNECT] socket");
        return;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TEST_PORT);
    if (inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr) != 1) {
        fprintf(stderr, "[SOCKET/CONNECT] inet_pton failed\n");
        close(sock);
        return;
    }

    printf("[SOCKET/CONNECT] connect() to 127.0.0.1:%d\n", TEST_PORT);

    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        /* Expected: nothing is listening on this port. */
        printf("[SOCKET/CONNECT] connect failed as expected (%s)\n",
               strerror(errno));
    } else {
        printf("[SOCKET/CONNECT] connect unexpectedly succeeded\n");
    }

    close(sock);
    printf("[SOCKET/CONNECT] socket closed\n");
}

/* ---------------------------------------------------------------- */
/* [EXECVE] child #1: replace itself with a harmless binary. */
static void child_execve(void)
{
    printf("[EXECVE] child pid=%d executing /bin/echo\n", getpid());

    char *argv[] = { "/bin/echo", "rule_test:execve-child", NULL };
    char *envp[] = { NULL };

    execve("/bin/echo", argv, envp);

    /* Only reached if /bin/echo is missing; fall back, then bail. */
    perror("[EXECVE] execve /bin/echo failed, trying /bin/true");
    char *argv2[] = { "/bin/true", NULL };
    execve("/bin/true", argv2, envp);

    perror("[EXECVE] execve /bin/true failed");
    _exit(127);
}

/* ---------------------------------------------------------------- */
/* [FORK] child #2: plain worker that just does a little CPU work
 * and exits, to exercise fork/wait without any execve.
 */
static void child_worker(void)
{
    printf("[FORK] worker child pid=%d running\n", getpid());

    volatile long acc = 0;
    for (int i = 0; i < 100000; i++)
        acc += i;

    printf("[FORK] worker child pid=%d done (acc=%ld)\n", getpid(), acc);
    _exit(0);
}

/* ---------------------------------------------------------------- */
/* [FORK] spawn exactly two children (execve child, worker child)
 * and wait for both deterministically.
 */
static void step_fork_wait(void)
{
    printf("[FORK] forking execve child\n");
    pid_t pid1 = fork();

    if (pid1 == -1) {
        perror("[FORK] fork (execve child)");
    } else if (pid1 == 0) {
        child_execve();
        _exit(127); /* unreachable */
    }

    printf("[FORK] forking worker child\n");
    pid_t pid2 = fork();

    if (pid2 == -1) {
        perror("[FORK] fork (worker child)");
    } else if (pid2 == 0) {
        child_worker();
        _exit(0); /* unreachable */
    }

    int status;

    if (pid1 > 0) {
        pid_t w = waitpid(pid1, &status, 0);
        if (w == -1)
            perror("[FORK] waitpid (execve child)");
        else
            printf("[FORK] execve child pid=%d reaped, status=0x%x\n",
                   w, status);
    }

    if (pid2 > 0) {
        pid_t w = wait4(pid2, &status, 0, NULL);
        if (w == -1)
            perror("[FORK] wait4 (worker child)");
        else
            printf("[FORK] worker child pid=%d reaped, status=0x%x\n",
                   w, status);
    }
}

/* ---------------------------------------------------------------- */
/* Remove the temp file created during the test. */
static void cleanup(const char *path)
{
    if (path[0] == '\0')
        return;

    printf("[CLEANUP] removing %s\n", path);
    if (unlink(path) == -1)
        perror("[CLEANUP] unlink");
    else
        printf("[CLEANUP] unlink OK\n");
}

/* ---------------------------------------------------------------- */
int main(void)
{
    char temp_path[256] = { 0 };

    printf("=== rule_test starting (pid=%d) ===\n", getpid());

    step_ptrace_self();

    if (step_open_read_close(temp_path, sizeof(temp_path)) == 0)
        step_chmod(temp_path);

    step_mmap_mprotect();
    step_socket_connect();
    step_fork_wait();

    cleanup(temp_path);

    printf("=== rule_test complete ===\n");
    return 0;
}