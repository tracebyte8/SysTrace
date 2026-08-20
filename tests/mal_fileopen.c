// Simulates a makeattern (the kind of
// behavior ransomware or info-stealers show: opening many files fast).
// Only touches files it creates itself in /tmp — nothing pre-existing.
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#define FILE_COUNT 30

int main(void)
{
    char path[64];

    // First create disposable files so this test doesn't depend on
    // anything already on disk.
    for (int i = 0; i < FILE_COUNT; i++) {
        snprintf(path, sizeof(path), "/tmp/mal_test_file_%d.tmp", i);
        int fd = open(path, O_CREAT | O_WRONLY, 0600);
        if (fd >= 0) {
            write(fd, "x", 1);
            close(fd);
        }
    }

    // Now rapidly open/read/close them all — this is the suspicious burst
    for (int i = 0; i < FILE_COUNT; i++) {
        snprintf(path, sizeof(path), "/tmp/mal_test_file_%d.tmp", i);
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            char buf[1];
            read(fd, buf, 1);
            close(fd);
        }
    }

    // Cleanup
    for (int i = 0; i < FILE_COUNT; i++) {
        snprintf(path, sizeof(path), "/tmp/mal_test_file_%d.tmp", i);
        unlink(path);
    }

    printf("mal_fileopen: done (%d files touched)\n", FILE_COUNT);
    return 0;
}
