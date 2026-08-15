#include <stdio.h>

#include "index.h"
#include "tracer.h"

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: %s <program>\n", argv[0]);
        return 1;
    }


    trace(argv[1]);
    html(argv[1]);


    printf("Report generated: report.html\n");

    return 0;
}