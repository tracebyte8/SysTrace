#include "report.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>

/* ===================== INTERNAL STATE ===================== */

typedef enum {
    SEC_PROCESS = 0,
    SEC_FILE,
    SEC_NETWORK,
    SEC_MEMORY,
    SEC_COUNT
} section_t;

static const char *section_titles[SEC_COUNT] = {
    "Process Monitor",
    "File Monitor",
    "Network Monitor",
    "Memory Monitor"
};

static const char *section_ids[SEC_COUNT] = {
    "process-monitor",
    "file-monitor",
    "network-monitor",
    "memory-monitor"
};


typedef struct {
    char *text;
    size_t repeat;
} event_t;

static FILE *fp = NULL;
static char *program_name = NULL;

static event_t *events[SEC_COUNT];
static size_t event_count[SEC_COUNT];
static size_t event_cap[SEC_COUNT];

/* Summary counters, updated inline as events are recorded. */
static size_t stat_processes_created = 0;
static size_t stat_files_opened = 0;
static size_t stat_files_read = 0;
static size_t stat_sockets_created = 0;
static size_t stat_connections = 0;
static size_t stat_memory_ops = 0;

/* ===================== INTERNAL HELPERS ===================== */

static char *dup_str(const char *s)
{
    size_t len = strlen(s) + 1;
    char *out = malloc(len);
    if (!out)
        return NULL;
    memcpy(out, s, len);
    return out;
}


static int is_printable_ascii(const char *s)
{
    if (!s)
        return 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if (*p < 0x20 || *p > 0x7E)
            return 0;
    }
    return 1;
}


static const char *safe_str(const char *s)
{
    if (!s || s[0] == '\0')
        return "(unknown)";
    if (!is_printable_ascii(s))
        return "(unreadable filename)";
    return s;
}

static void reset_events(void)
{
    for (int s = 0; s < SEC_COUNT; s++) {
        for (size_t i = 0; i < event_count[s]; i++)
            free(events[s][i].text);
        free(events[s]);
        events[s] = NULL;
        event_count[s] = 0;
        event_cap[s] = 0;
    }
    free(program_name);
    program_name = NULL;

    stat_processes_created = 0;
    stat_files_opened = 0;
    stat_files_read = 0;
    stat_sockets_created = 0;
    stat_connections = 0;
    stat_memory_ops = 0;
}

static void push_event(section_t sec, char *text)
{
    if (!text)
        return;

    if (event_count[sec] > 0) {
        event_t *last = &events[sec][event_count[sec] - 1];
        if (strcmp(last->text, text) == 0) {
            last->repeat++;
            free(text);
            return;
        }
    }

    if (event_count[sec] == event_cap[sec]) {
        size_t new_cap = event_cap[sec] ? event_cap[sec] * 2 : 16;
        event_t *tmp = realloc(events[sec], new_cap * sizeof(event_t));
        if (!tmp) {
            free(text);
            return;
        }
        events[sec] = tmp;
        event_cap[sec] = new_cap;
    }

    events[sec][event_count[sec]].text = text;
    events[sec][event_count[sec]].repeat = 1;
    event_count[sec]++;
}


static void add_event(section_t sec, const char *fmt, ...)
{
    if (!fp)
        return;

    va_list args, args_copy;
    va_start(args, fmt);
    va_copy(args_copy, args);

    int needed = vsnprintf(NULL, 0, fmt, args_copy);
    va_end(args_copy);

    if (needed < 0) {
        va_end(args);
        return;
    }

    char *buf = malloc((size_t)needed + 1);
    if (!buf) {
        va_end(args);
        return;
    }

    vsnprintf(buf, (size_t)needed + 1, fmt, args);
    va_end(args);

    push_event(sec, buf);
}


static void write_section(section_t sec)
{
    fprintf(fp, "<div class=\"monitor\" id=\"%s\">\n", section_ids[sec]);
    fprintf(fp, "<h2>%s</h2>\n", section_titles[sec]);

    if (event_count[sec] == 0) {
        fprintf(fp, "<p class=\"empty\">No events recorded.</p>\n");
    } else {
        fprintf(fp, "<ul>\n");
        for (size_t i = 0; i < event_count[sec]; i++) {
            if (events[sec][i].repeat > 1) {
                fprintf(fp, "<li>%s <span class=\"repeat\">(x%zu)</span></li>\n",
                    events[sec][i].text, events[sec][i].repeat);
            } else {
                fprintf(fp, "<li>%s</li>\n", events[sec][i].text);
            }
        }
        fprintf(fp, "</ul>\n");
    }

    fprintf(fp, "</div>\n");
}

static void write_summary(void)
{
    fprintf(fp, "<div id=\"summary\">\n");
    fprintf(fp, "<h2>Summary</h2>\n");
    fprintf(fp, "<ul>\n");
    fprintf(fp, "<li>Program: %s</li>\n", program_name ? program_name : "(unknown)");
    fprintf(fp, "<li>Processes created: %zu</li>\n", stat_processes_created);
    fprintf(fp, "<li>Files opened: %zu</li>\n", stat_files_opened);
    fprintf(fp, "<li>Files read: %zu</li>\n", stat_files_read);
    fprintf(fp, "<li>Sockets created: %zu</li>\n", stat_sockets_created);
    fprintf(fp, "<li>Connections: %zu</li>\n", stat_connections);
    fprintf(fp, "<li>Memory operations: %zu</li>\n", stat_memory_ops);
    fprintf(fp, "</ul>\n");
    fprintf(fp, "</div>\n");
}

/* ----- Symbolic name lookups for the Network Monitor (issue #4) ----- */

static const char *af_name(long long domain)
{
    switch (domain) {
        case 0:  return "AF_UNSPEC";
        case 1:  return "AF_UNIX";
        case 2:  return "AF_INET";
        case 10: return "AF_INET6";
        case 16: return "AF_NETLINK";
        case 17: return "AF_PACKET";
        default: return NULL;
    }
}

static const char *socktype_name(long long type)
{

    switch (type & 0xf) {
        case 1: return "SOCK_STREAM";
        case 2: return "SOCK_DGRAM";
        case 3: return "SOCK_RAW";
        case 5: return "SOCK_SEQPACKET";
        default: return NULL;
    }
}

static const char *ipproto_name(long long protocol)
{
    switch (protocol) {
        case 0:  return "IPPROTO_IP";
        case 1:  return "IPPROTO_ICMP";
        case 6:  return "IPPROTO_TCP";
        case 17: return "IPPROTO_UDP";
        case 41: return "IPPROTO_IPV6";
        default: return NULL;
    }
}


static void sym_or_num(char *buf, size_t bufsz, const char *name, long long value)
{
    if (name)
        snprintf(buf, bufsz, "%s", name);
    else
        snprintf(buf, bufsz, "%lld", value);
}

/* ===================== LIFECYCLE ===================== */

void report_start(const char *program)
{
 
    reset_events();

    fp = fopen("report.html", "w");
    if (!fp) {
        fprintf(stderr, "fopen failed: %s\n", strerror(errno));
        return;
    }

    program_name = dup_str(safe_str(program));

    for (int s = 0; s < SEC_COUNT; s++) {
        events[s] = NULL;
        event_count[s] = 0;
        event_cap[s] = 0;
    }
}

void report_finish(void)
{
    if (!fp)
        return;

    fprintf(fp,
        "<!DOCTYPE html>\n"
        "<html>\n"
        "<head>\n"
        "<meta charset=\"UTF-8\">\n"
        "<title>Sandbox Report</title>\n"
        "<link rel=\"stylesheet\" href=\"style.css\">\n"
        "</head>\n"
        "<body>\n");

    fprintf(fp,
        "<h1>Sandbox Report</h1>\n"
        "<h3>Program : %s</h3>\n",
        program_name ? program_name : "(unknown)");

    write_summary();

    fprintf(fp, "<div id=\"monitors\">\n");
    write_section(SEC_PROCESS);
    write_section(SEC_FILE);
    write_section(SEC_NETWORK);
    write_section(SEC_MEMORY);
    fprintf(fp, "</div>\n");

    fprintf(fp, "</body>\n");
    fprintf(fp, "</html>\n");

    fclose(fp);
    fp = NULL;

    reset_events();
}

/* ===================== PROCESS ===================== */

void report_process_section_exec(const char *filename)
{
    add_event(SEC_PROCESS, "execve(\"%s\")", safe_str(filename));
}

void report_process_section_fork(pid_t pid)
{
    stat_processes_created++;
    add_event(SEC_PROCESS, "fork() -&gt; pid %d", pid);
}

void report_process_section_wait(pid_t pid)
{
    add_event(SEC_PROCESS, "waitpid(%d)", pid);
}

/* ===================== FILE ===================== */

void report_file_section_open(const char *filename, long long dirfd, int flags)
{
    stat_files_opened++;
    add_event(SEC_FILE, "open(\"%s\") | dirfd=%lld, flags=%d", safe_str(filename), dirfd, flags);
}

void report_file_section_read(int fd, const char *path, int bytes)
{
    stat_files_read++;
    if (path)
        add_event(SEC_FILE, "read(fd=%d (%s), %d bytes)", fd, safe_str(path), bytes);
    else
        add_event(SEC_FILE, "read(fd=%d, %d bytes)", fd, bytes);
}

void report_file_section_close(int fd, const char *path)
{
    if (path)
        add_event(SEC_FILE, "close(fd=%d (%s))", fd, safe_str(path));
    else
        add_event(SEC_FILE, "close(fd=%d)", fd);
}

/* ===================== NETWORK ===================== */

void report_network_section_connect(long long fd, const char *path, long long result)
{
    stat_connections++;
    if (path)
        add_event(SEC_NETWORK, "connect(fd=%lld (%s)) | result=%lld", fd, safe_str(path), result);
    else
        add_event(SEC_NETWORK, "connect(fd=%lld) | result=%lld", fd, result);
}

void report_network_section_send(int fd, const char *path, int bytes)
{
    if (path)
        add_event(SEC_NETWORK, "send(fd=%d (%s), %d bytes)", fd, safe_str(path), bytes);
    else
        add_event(SEC_NETWORK, "send(fd=%d, %d bytes)", fd, bytes);
}

void report_network_section_recv(int fd, const char *path, int bytes)
{
    if (path)
        add_event(SEC_NETWORK, "recv(fd=%d (%s), %d bytes)", fd, safe_str(path), bytes);
    else
        add_event(SEC_NETWORK, "recv(fd=%d, %d bytes)", fd, bytes);
}

void report_network_section_accept(int fd, const char *path, int result)
{
    if (path)
        add_event(SEC_NETWORK, "accept(fd=%d (%s)) | result=%d", fd, safe_str(path), result);
    else
        add_event(SEC_NETWORK, "accept(fd=%d) | result=%d", fd, result);
}

void report_network_section_bind(int fd, const char *path, int result)
{
    if (path)
        add_event(SEC_NETWORK, "bind(fd=%d (%s)) | result=%d", fd, safe_str(path), result);
    else
        add_event(SEC_NETWORK, "bind(fd=%d) | result=%d", fd, result);
}

void report_network_section_listen(int fd, const char *path, int result)
{
    if (path)
        add_event(SEC_NETWORK, "listen(fd=%d (%s)) | result=%d", fd, safe_str(path), result);
    else
        add_event(SEC_NETWORK, "listen(fd=%d) | result=%d", fd, result);
}

void report_network_section_socket(long long domain, long long type, long long protocol)
{
    stat_sockets_created++;

    char dbuf[32], tbuf[32], pbuf[32];
    sym_or_num(dbuf, sizeof dbuf, af_name(domain), domain);
    sym_or_num(tbuf, sizeof tbuf, socktype_name(type), type);
    sym_or_num(pbuf, sizeof pbuf, ipproto_name(protocol), protocol);

    add_event(SEC_NETWORK, "socket(%s, %s, %s)", dbuf, tbuf, pbuf);
}

/* ===================== MEMORY ===================== */

void report_memory_section_mmap(pid_t pid, unsigned long long length, long long prot,
    long long flags, long long fd, long long ret)
{
    stat_memory_ops++;
    add_event(SEC_MEMORY,
        "mmap(pid=%d, length=0x%llx, prot=%lld, flags=%lld, fd=%lld) -&gt; 0x%llx",
        pid, length, prot, flags, fd, ret);
}

void report_memory_section_mprotect(pid_t pid, unsigned long long addr, long long length,
    long long prot, long long ret)
{
    stat_memory_ops++;
    add_event(SEC_MEMORY,
        "mprotect(pid=%d, addr=0x%llx, length=%lld, prot=%lld) -&gt; %lld",
        pid, addr, length, prot, ret);
}

void report_memory_section_munmap(pid_t pid, unsigned long long addr, long long length, long long ret)
{
    stat_memory_ops++;
    add_event(SEC_MEMORY,
        "munmap(pid=%d, addr=0x%llx, length=%lld) -&gt; %lld",
        pid, addr, length, ret);
}