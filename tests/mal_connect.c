// Simulates C2-beacon-like behavior: repeated connect() attempts at
// short intervals. Only ever targets 127.0.0.1 on a high port that's
// almost certainly closed, so this never actually reaches the network.
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define ATTEMPTS 12
#define TARGET_PORT 54321

int main(void)
{
    for (int i = 0; i < ATTEMPTS; i++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("socket");
            continue;
        }

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(TARGET_PORT);
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

        // This will typically fail (connection refused) since nothing
        // is listening — that's fine, the syscall itself is what's traced.
        connect(sock, (struct sockaddr *)&addr, sizeof(addr));

        close(sock);
        usleep(50000); // beacon-like interval
    }

    printf("mal_connect: done (%d attempts)\n", ATTEMPTS);
    return 0;
}
