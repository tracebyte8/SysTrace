#include <stdio.h>

#include "report.h"
#include "tracer.h"

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: %s <program>\n", argv[0]);
        return 1;
    }

    report_start(argv[1]);

    trace(argv[1]);

    report_finish();

    printf("Report generated: report.html\n");

    return 0;
}