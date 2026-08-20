#include <stdio.h>
#include "stat.h"
#include "dataset.h"
#include "rules.h"

void save_dataset(const char *program,int labee)
{
    FILE *fp = fopen("features.json", "w");

    if (fp == NULL) {
        perror("features.json");
        return;
    }
printf("DATASET: file=%d process=%d network=%d fork=%d connect=%d "
       "execve=%d read=%d open=%d close=%d memory=%d chmod=%d "
       "killit=%d label=%d\n",
       stats.file,
       stats.process,
       stats.network,
       stats.fork,
       stats.connect,
       stats.execve,
       stats.read,
       stats.open,
       stats.close,
       stats.memory,
       stats.chmod,
       stats.killit,
       label);


fprintf(fp, "{\n");
fprintf(fp, "  \"file\": %d,\n", stats.file);
fprintf(fp, "  \"process\": %d,\n", stats.process);
fprintf(fp, "  \"network\": %d,\n", stats.network);
fprintf(fp, "  \"fork\": %d,\n", stats.fork);
fprintf(fp, "  \"connect\": %d,\n", stats.connect);
fprintf(fp, "  \"execve\": %d,\n", stats.execve);
fprintf(fp, "  \"read\": %d,\n", stats.read);
fprintf(fp, "  \"open\": %d,\n", stats.open);
fprintf(fp, "  \"close\": %d,\n", stats.close);
fprintf(fp, "  \"memory\": %d,\n", stats.memory);
fprintf(fp, "  \"chmod\": %d,\n", stats.chmod);
fprintf(fp, "  \"killit\": %d\n", stats.killit);
fprintf(fp, "}\n");


    fclose(fp);
}