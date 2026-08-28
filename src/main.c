#include <stdio.h>
#include <stdlib.h>

#include "index.h"
#include "tracer.h"
#include "dataset.h"
#include "stat.h"
#include "rules.h"


int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: %s <program>\n", argv[0]);
        return 1;
    }

    printf("DEBUG: starting trace()\n");

    pid_t pid =  trace(argv[1]); // get pid 

    printf("DEBUG: trace() returned\n");

    printf("DEBUG: creating features.json\n");

    save_dataset(argv[1], label, pid);

    printf("DEBUG: features.json created\n");

    printf("DEBUG: running ML prediction\n");

    int result = system("python3 ml/predict.py");

    if (result != 0) {
        fprintf(stderr,
                "ERROR: ml/predict.py failed, return code=%d\n",
                result);
    }

    printf("DEBUG: ML prediction finished\n");

    html(argv[1],pid);
    remove_sta(pid);

    reset_stats();


    return 0;
}