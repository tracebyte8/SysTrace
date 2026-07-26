#ifndef MEMORY_H
#define MEMORY_H

#include <sys/types.h>

void read_string(pid_t pid, unsigned long addr, char *buffer, int max);

#endif