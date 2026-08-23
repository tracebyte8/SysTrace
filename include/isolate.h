#ifndef ISOLATE_H
#define ISOKATE_H
#include <unistd.h>

static int child_function(void *arg);
pid_t create_namespace(char **target_argv);
#endif