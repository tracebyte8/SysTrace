#ifndef EVENT_H
#define EVENT_H

#include <sys/types.h>
typedef enum
{
    EVENT_FILE_OPEN,
    EVENT_FILE_READ,
    EVENT_FILE_WRITE,
    EVENT_FILE_DELETE,
    EVENT_PROCESS_EXEC,
    EVENT_PROCESS_FORK,
    EVENT_NETWORK_CONNECT,
    EVENT_NETWORK_SEND
    
} EventType;

typedef struct
{
    pid_t pid;

    EventType type;

    char syscall[32];

    char path[256];

    int port;
} event;

#endif