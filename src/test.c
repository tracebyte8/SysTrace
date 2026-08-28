#include <unistd.h>
#include <sys/wait.h>

int main()
{
    for (int i = 0; i < 10; i++) {

        pid_t pid = fork();

        if (pid == 0) {
            return 0;
        }

        wait(NULL);
    }

    return 0;
}