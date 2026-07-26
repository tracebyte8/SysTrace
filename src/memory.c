#include "memory.h"
#include <sys/ptrace.h>
#include <string.h>


// read_string() follows that address and copies the bytes into your own buffer:


  void read_string(pid_t pid,
                   unsigned long addr,
                   char *buffer,int max){
               
    int copied = 0;
    long data;

    while (copied < max)
    {
        data = ptrace(PTRACE_PEEKDATA,
                      pid,
                      addr + copied,
                      NULL);

        memcpy(buffer + copied,
               &data,
               sizeof(long));

        if (memchr(&data, '\0', sizeof(long)))
            break;

        copied += sizeof(long);
    }

    buffer[max - 1] = '\0';
}