#include <stdio.h>
#include <string.h>

#include "tracer.h"
#include "stat.h"
#include "rules.h"
#include "score.h"

int give_danger(char word[100], double score_model)
{
    int danger = 0;
    int risk = compute_main_risk_score();

    if (risk >= 70 && score_model >= 60.0) {
        danger = 100;
    }
    else if (risk >= 70) {
        danger = 85;
    }
    else if (strcmp(word, "MALICIOUS") == 0 && score_model >= 80.0) {
        danger = 80;
    }
    else if (risk >= 50 && score_model >= 50.0) {
        danger = 65;
    }
    else if (risk >= 40) {
        danger = 50;
    }
    else if (strcmp(word, "MALICIOUS") == 0 && score_model >= 50.0) {
        danger = 45;
    }
    else if (risk >= 20) {
        danger = 25;
    }
    else {
        danger = 10;
    }

    return danger;
}


void html(char *program, pid_t pid)
{
    (void)pid;

    FILE *fp = fopen("security_report.html", "w");

    if (fp == NULL) {
        perror("security_report.html");
        return;
    }

    FILE *fptr = fopen("prediction.txt", "r");

    if (fptr == NULL) {
        perror("prediction.txt");
        fclose(fp);
        return;
    }

    char word[100] = {0};
    double score = 0.0;

    if (fgets(word, sizeof(word), fptr) == NULL) {
        fprintf(stderr, "ERROR: cannot read prediction\n");
        fclose(fptr);
        fclose(fp);
        return;
    }

    word[strcspn(word, "\n")] = '\0';

    if (fscanf(fptr, "%lf", &score) != 1) {
        fprintf(stderr, "ERROR: cannot read model score\n");
        fclose(fptr);
        fclose(fp);
        return;
    }

    fclose(fptr);


    /*
     * all_stats contains the aggregated statistics
     * from all traced processes.
     */

    int danger = give_danger(
        word,
        score
    );


    fprintf(fp,
        "<!DOCTYPE html>\n"
        "<html lang=\"en\">\n"
        "<head>\n"
        "    <meta charset=\"UTF-8\">\n"
        "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n"
        "    <title>System Call Monitor</title>\n"
        "    <link rel=\"stylesheet\" href=\"dashboard/style.css\">\n"
        "</head>\n"

        "<body>\n"

        "    <h1>System Call Monitor</h1>\n"
        "    <h3>%s</h3>\n"

        "    <section id=\"summary\">\n"
        "        <h2>Summary</h2>\n"
        "        <ul>\n"

        "            <li>Processes created: %d</li>\n"
        "            <li>Files opened: %d</li>\n"
        "            <li>Files read: %d</li>\n"
        "            <li>Connections: %d</li>\n"
        "            <li>Memory operations: %d</li>\n"
        "            <li>Blocked processes: %d</li>\n"

        "        </ul>\n"
        "    </section>\n"

        "    <section id=\"files\">\n"
        "        <h2>Reports</h2>\n"
        "        <div class=\"file-links\">\n"

        "            <a href=\"alerts.json\">JSON Alerts</a>\n"
        "            <a href=\"log.txt\">Text logs</a>\n"
        "            <a href=\"syscall.txt\">System calls</a>\n"

        "        </div>\n"
        "    </section>\n"

        "    <section id=\"danger\">\n"

        "        <div class=\"danger-circle\" "
        "style=\"--danger-percent:%d%%\">\n"

        "            <span class=\"danger-value\">%d%%</span>\n"

        "        </div>\n"

        "        <div class=\"danger-info\">\n"
        "            <h2>Danger Level</h2>\n"

        "            <p>Rule engine score: %d%%</p>\n"
        "            <p>ML prediction: %s</p>\n"
        "            <p>ML confidence: %.2f%%</p>\n"
        "            <p>Dangerous events: %d</p>\n"

        "        </div>\n"

        "    </section>\n"

        "    <footer>Linux System Call Monitor</footer>\n"

        "</body>\n"
        "</html>\n",

        program,

        all_stats.fork,
        all_stats.open,
        all_stats.read,
        all_stats.connect,
        all_stats.memory + all_stats.mprotect,
        all_stats.killit,

        danger,
        danger,

        compute_main_risk_score(),
        word,
        score,
        all_stats.dangerous_events
    );


    fclose(fp);

    printf("REPORT: security_report.html created\n");
    printf("Rule engine score: %d%%\n", compute_main_risk_score());
    printf("ML prediction: %s\n", word);
    printf("ML confidence: %.2f%%\n", score);
    printf("Final danger: %d%%\n", danger);
        printf("Danger events: %d\n", all_stats.dangerous_events);

}
