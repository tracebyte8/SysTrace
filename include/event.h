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
    EVENT_NETWORK_SOCKET,
    EVENT_NETWORK_SEND,
    EVENT_MEMORY_MPROTECT,
    EVENT_PRCOESS_PTRACE
} EventType;


typedef enum {
    INFO,//    0
    LOW,//     1
    MEDIUM,//  2
    HIGH,//    3
    CRITICAL// 4
} severity_t;

typedef struct
{
    severity_t severity;

    pid_t pid;

    EventType type;

    char syscall[32];

    char path[256];

    int port;
} event;

#endif