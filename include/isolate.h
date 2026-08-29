#ifndef ISOLATE_H
#define ISOLATE_H

#include <sys/types.h>

pid_t create_namespace(char **target_argv);

#endif