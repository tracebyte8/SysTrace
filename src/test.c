// Simulates a shellcode-injection / self-modifying-code pattern:
// repeatedly maps memory, then flips it executable via mprotect.
// This is the kind of syscall sequence AV/EDR tools flag as suspicious.
#include <stdio.h>
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>

#define ROUNDS 20
#define PAGE_SIZE 4096

int main(void)
{
    for (int i = 0; i < ROUNDS; i++) {
        void *mem = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mem == MAP_FAILED) {
            perror("mmap");
            continue;
        }

        // Write a harmless byte pattern (no real shellcode)
        memset(mem, 0x90, 16); // NOP-like filler, never executed for real

        // Flip page to executable — this is the suspicious step
        if (mprotect(mem, PAGE_SIZE, PROT_READ | PROT_EXEC) != 0) {
            perror("mprotect");
        }

        munmap(mem, PAGE_SIZE);
        usleep(10000); // small delay so the trace isn't instantaneous
    }

    printf("mal_mmap_mprotect: done (%d rounds)\n", ROUNDS);
    return 0;
}
