#include "set_root.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

#define ROOTFS "/tmp/systrace-root"


static int copy_file(
    const char *src,
    const char *dst
)
{
    int src_fd = open(src, O_RDONLY);

    if (src_fd == -1) {
        perror(src);
        return -1;
    }


    int dst_fd = open(
        dst,
        O_WRONLY | O_CREAT | O_TRUNC,
        0755
    );

    if (dst_fd == -1) {

        perror(dst);

        close(src_fd);

        return -1;
    }


    char buffer[8192];

    ssize_t bytes_read;


    while (
        (bytes_read =
            read(
                src_fd,
                buffer,
                sizeof(buffer)
            )
        ) > 0
    ) {

        ssize_t total_written = 0;


        while (total_written < bytes_read) {

            ssize_t bytes_written =
                write(
                    dst_fd,
                    buffer + total_written,
                    bytes_read - total_written
                );


            if (bytes_written == -1) {

                perror("write");

                close(src_fd);
                close(dst_fd);

                return -1;
            }


            total_written += bytes_written;
        }
    }


    if (bytes_read == -1) {

        perror("read");

        close(src_fd);
        close(dst_fd);

        return -1;
    }


    close(src_fd);
    close(dst_fd);

    return 0;
}


static int copy_standard_runtime(void)
{
    if (
        copy_file(
            "/usr/lib/libc.so.6",
            ROOTFS "/usr/lib/libc.so.6"
        ) == -1
    ) {

        return -1;
    }


    if (
        copy_file(
            "/lib64/ld-linux-x86-64.so.2",
            ROOTFS "/lib64/ld-linux-x86-64.so.2"
        ) == -1
    ) {

        return -1;
    }


    return 0;
}


static int copy_target(
    const char *target
)
{
    if (
        copy_file(
            target,
            ROOTFS "/basic_target"
        ) == -1
    ) {

        perror("copy target");

        return -1;
    }


    return 0;
}


int set_up_root(
    const char *target
)
{
    if (
        mkdir(ROOTFS, 0755) == -1 &&
        errno != EEXIST
    ) {

        perror("mkdir rootfs");

        return -1;
    }


    if (
        mkdir(ROOTFS "/oldroot", 0755) == -1 &&
        errno != EEXIST
    ) {

        perror("mkdir oldroot");

        return -1;
    }


    if (
        mkdir(ROOTFS "/tmp", 0755) == -1 &&
        errno != EEXIST
    ) {

        perror("mkdir tmp");

        return -1;
    }


    if (
        mkdir(ROOTFS "/proc", 0755) == -1 &&
        errno != EEXIST
    ) {

        perror("mkdir proc");

        return -1;
    }


    if (
        mkdir(ROOTFS "/etc", 0755) == -1 &&
        errno != EEXIST
    ) {

        perror("mkdir etc");

        return -1;
    }


    if (
        mkdir(ROOTFS "/usr", 0755) == -1 &&
        errno != EEXIST
    ) {

        perror("mkdir usr");

        return -1;
    }


    if (
        mkdir(ROOTFS "/usr/bin", 0755) == -1 &&
        errno != EEXIST
    ) {

        perror("mkdir usr/bin");

        return -1;
    }


    if (
        mkdir(ROOTFS "/usr/lib", 0755) == -1 &&
        errno != EEXIST
    ) {

        perror("mkdir usr/lib");

        return -1;
    }


    if (
        mkdir(ROOTFS "/lib", 0755) == -1 &&
        errno != EEXIST
    ) {

        perror("mkdir lib");

        return -1;
    }


    if (
        mkdir(ROOTFS "/lib64", 0755) == -1 &&
        errno != EEXIST
    ) {

        perror("mkdir lib64");

        return -1;
    }


    if (copy_target(target) == -1)
        return -1;


    if (copy_standard_runtime() == -1) {

        perror("copy standard runtime");

        return -1;
    }


    return 0;
}