#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>

extern char **environ;

int main(void)
{
    char buffer[64];

    /* -------- open / read / close / write -------- */

    int fd = open("/etc/passwd", O_RDONLY);

    if (fd == -1)
    {
        perror("open");
        return 1;
    }

    ssize_t n = read(fd, buffer, sizeof(buffer) - 1);

    if (n > 0)
    {
        buffer[n] = '\0';
        write(STDOUT_FILENO, buffer, n);
    }

    close(fd);

    /* -------- fork -------- */

    pid_t pid = fork();

    if (pid == -1)
    {
        perror("fork");
        return 1;
    }

    if (pid == 0)
    {
        /* -------- execve -------- */

        char *argv[] = {
            "/bin/ls",
            "-l",
            NULL
        };

        execve("/bin/ls", argv, environ);

        perror("execve");
        return 1;
    }

    wait(NULL);

    return 0;
}