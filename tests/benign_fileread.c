// A normal, boring program: creates one file, reads it once, exits.
// This is what "ordinary" file behavior looks like to your monitor.
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main(void)
{
    const char *path = "/tmp/benign_test_file.tmp";

    int fd = open(path, O_CREAT | O_WRONLY, 0600);
    if (fd >= 0) {
        write(fd, "hello world\n", 12);
        close(fd);
    }

    fd = open(path, O_RDONLY);
    if (fd >= 0) {
        char buf[64];
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n > 0) {
            write(STDOUT_FILENO, buf, n);
        }
        close(fd);
    }

    unlink(path);

    printf("benign_fileread: done\n");
    return 0;
}
