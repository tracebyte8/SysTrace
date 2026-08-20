#include "stat.h"

syscall_stat stats = {0};

void reset_stats(void)
{
    stats = (syscall_stat){0};
}