#include "alert.h"

static FILE *log_file = NULL;

void open_alert(void){
  log_file=fopen("alert_log.txt","a");
   if (!log_file){
    perror("error open log ");
   }
 }


 void write_alert(const char *pathname){
   fputs(pathname,log_file);
   fputs("\n",log_file);
   }

   void close_alert(void){
    fclose(log_file);
}