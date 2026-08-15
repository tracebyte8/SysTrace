#include <stdio.h>
#include "tracer.h"

void html(char *program)
{
    FILE *fp = fopen("report.html", "w");

    if (!fp)
    {
        perror("report.html");
        return;
    }
 
 process = process + forkit + excve;
file = openit + readit;
network = connectit;
int total = process + file + network;

int danger = 0;

if (total > 0)
    danger = ((double)killit * 100) / (double)total;

if (danger > 100 || killit !=0 )
    danger = 100;
    printf("DEBUG: killit=%d total=%d\n", killit, total);

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
                     "<a href=\"syscall.txt\">system calls</a>\n"
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
        "            <p> 100% indicates that a dangerous event was detected and the monitored process was blocked. Additional suspicious syscalls may have been not detected before the process was terminated. </p>\n"
        "        </div>\n"
        "    </section>\n"

        "    <footer>Linux System Call Monitor</footer>\n"

        "</body>\n"
        "</html>\n",

        program,
        forkit,
        openit,
        readit,
        connectit,
        memory + chmod,
        killit,
        danger,
        danger,
        killit
    );

    fclose(fp);
}