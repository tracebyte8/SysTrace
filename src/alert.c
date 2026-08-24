#include "alert.h"
#include "event.h"
#include <time.h>

// alert.c is for manage files (alert.json,log.txt,syscall.txt)

FILE *syscall_file= NULL;
static FILE *log_file = NULL;
static FILE *alerts_json = NULL;

//

 void open_alert(void){

    log_file=fopen("log.txt","a");
   
    if (!log_file){
       perror("error open log ");
      }

  alerts_json=fopen("alerts.json","a");
  
    if (!alerts_json){
        perror("error open alert ");
       }

   syscall_file=fopen("syscall.txt","a");
  
    if (!syscall_file){
        perror("error open syscall ");
       }
   
 }

//
 void write_alert(const char *pathname){

   fputs(pathname,log_file);
   fputs("\n",log_file);
  
  }

//
   void alert_high(event *event,const char *details){
    char timebuf[64];

   time_t now = time(NULL);
   struct tm *tm = gmtime(&now);

    strftime(timebuf,
                     sizeof(timebuf),
                    "%Y-%m-%dT%H:%M:%SZ",
                                      tm);
              
      if (!alerts_json) {
          printf("alerts_json is NULL!\n");
          return;
        }
   
fprintf(alerts_json,
         
        "{\n"
        "\"time\":\"%s\",\n"
        "\"severity\":%d,\n"
        "\"pid\":%d,\n"
        "\"syscall\":\"%s\",\n"
        "\"path\":\"%s\",\n"
        "\"action\":\"BLOCKED\",\n"
        "\"details\":\"%s\"}\n",
        timebuf,
        event->severity,
        event->pid,
        event->syscall,
        event->path,
        details);

        fflush(alerts_json);
}


//
   void close_alert(void){

    fclose(log_file);
    fclose(alerts_json);
    fclose(syscall_file);
   }