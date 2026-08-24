#include <stdio.h>
#include <string.h>

#include "tracer.h"
#include "stat.h"

void html(char *program, pid_t pid)
{
    char buffer[18] = {0};

    FILE *fp = fopen("security_report.html", "w");
    FILE *fpr = fopen("prediction.txt", "r");

    if (fp == NULL)
    {
        perror("security_report.html");
        return;
    }

    if (fpr != NULL)
    {
        if (fgets(buffer, sizeof(buffer), fpr) != NULL)
        {
            /* Remove newline from prediction.txt */
            buffer[strcspn(buffer, "\n")] = '\0';

            printf("Prediction: %s\n", buffer);
        }

        fclose(fpr);
    }

    syscall_stat *stats = get_stats(pid);

    if (stats == NULL)
    {
        fprintf(stderr, "ERROR: get_stats() returned NULL\n");
        fclose(fp);
        return;
    }

    int total = stats->file +
                stats->network +
                stats->process;

    int danger = 0;

    if (total > 0)
    {
        danger = (stats->killit * 100) / total;
    }

    /*
     * If the ML model classified the program as malicious,
     * display maximum danger.
     */
    if (strcmp(buffer, "MALICIOUS") == 0)
    {
        danger = 100;
    }

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

        "            <span class=\"danger-value\">%d</span>\n"

        "        </div>\n"

        "        <div class=\"danger-info\">\n"
        "            <h2>Danger Level</h2>\n"

        "            <p>%d dangerous event(s) detected.</p>\n"

        "            <p>"
        "100%% indicates that a dangerous event was detected "
        "and the monitored process was blocked. "
        "Additional suspicious syscalls may have been not "
        "detected before the process was terminated."
        "</p>\n"

        "        </div>\n"

        "    </section>\n"

        "    <footer>Linux System Call Monitor</footer>\n"

        "</body>\n"
        "</html>\n",

        program,

        /* Summary */
        stats->fork,
        stats->open,
        stats->read,
        stats->connect,
        stats->memory + stats->chmod,
        stats->killit,

        /* Danger circle */
        danger,

        /* Danger value */
        danger,

        /* Dangerous events */
        stats->killit
    );

    fclose(fp);

    printf("REPORT: security_report.html created\n");
}