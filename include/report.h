#ifndef REPORT_H
#define REPORT_H

#include <sys/types.h>

/* Lifecycle */
void report_start(const char *program);
void report_finish(void);

/* Process monitor */
void report_process_section_exec(const char *filename);
void report_process_section_fork(pid_t pid);
void report_process_section_wait(pid_t pid);

/* File monitor */
void report_file_section_open(const char *filename, long long dirfd, int flags);
void report_file_section_read(int fd, const char *path, int bytes);
void report_file_section_close(int fd, const char *path);

/* Network monitor */
void report_network_section_connect(long long fd, const char *path, long long result);
void report_network_section_send(int fd, const char *path, int bytes);
void report_network_section_recv(int fd, const char *path, int bytes);
void report_network_section_accept(int fd, const char *path, int result);
void report_network_section_bind(int fd, const char *path, int result);
void report_network_section_listen(int fd, const char *path, int result);
void report_network_section_socket(long long domain, long long type, long long protocol);

/* Memory monitor */
void report_memory_section_mmap(pid_t pid, unsigned long long length, long long prot,
    long long flags, long long fd, long long ret);
void report_memory_section_mprotect(pid_t pid, unsigned long long addr, long long length,
    long long prot, long long ret);
void report_memory_section_munmap(pid_t pid, unsigned long long addr, long long length, long long ret);

#endif /* REPORT_H */