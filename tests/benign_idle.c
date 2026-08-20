// The quietest possible baseline: just sleeps and exits.
// Useful as a near-zero-syscall-activity data point.
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    printf("benign_idle: starting\n");
    sleep(1);
    printf("benign_idle: done\n");
    return 0;
}
