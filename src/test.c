#include <stdio.h>
#include <unistd.h>

int main(void)
{
    printf("Hello from test program!\n");

    FILE *fp = fopen("test.txt", "w");
    if (fp) {
        fprintf(fp, "Sandbox test\n");
        fclose(fp);
    }

    sleep(1);

    return 0;
}