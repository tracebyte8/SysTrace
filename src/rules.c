#include "rules.h"
#include "alert.h"
#include <string.h>
#include <signal.h>



void check_danger(pid_t pid,EventType type,char syscall[32],char path[256],int porter){

   if (strcmp(path,"/etc/passwd")==0 || 
       strcmp(path,"/etc/shadow")==0 || 
       strcmp(syscall,"execve")==0   || 
       strcmp(syscall,"fork")==0){
 
        event e;
        e.type=type;
        strncpy(e.path, path, sizeof(e.path) - 1);
        e.path[sizeof(e.path) - 1] = '\0';
        e.pid=pid;
        strncpy(e.syscall, syscall, sizeof(e.syscall) - 1);
        e.syscall[sizeof(e.syscall) - 1] = '\0';       
        e.severity=CRITICAL;
        check_rules(&e);
    }


}



void check_rules(event *event){




    switch (event->type){
 
        // open
        case EVENT_FILE_OPEN:

               alert_high(event,"TRY TO OPEN FILE FOR PASSWORDS ");   
            
               if (kill(event->pid, SIGKILL) == -1)
                {
                  perror("kill");
                } 
              
           

           
         break;

        // read 
        case EVENT_FILE_READ:

            

              alert_high(event,"TRY TO READ PASSWORDS ");     
          
              if (kill(event->pid, SIGKILL) == -1)
                 {
                  perror("kill"); 
                  }
            
         break;


         // fork 
         case     EVENT_PROCESS_FORK:
      
                 
            alert_high(event,"TRY TO CREATE ANOTHER PROCESS");
                   if (kill(event->pid, SIGKILL) == -1)
                   {
                    perror("kill"); 

                   }
            
         break ;


          // execve
         case     EVENT_PROCESS_EXEC:
      
            
            alert_high(event,"TRY TO CHANGE THE PROG MISSION");
                  if (kill(event->pid, SIGKILL) == -1)
                   {
                    perror("kill"); 
                   }
           
         break;


         // CONNECT
         case     EVENT_NETWORK_CONNECT:
      
            
            alert_high(event,"TRY TO CONNECT WITH SOMEONE");
                  if (kill(event->pid, SIGKILL) == -1)
                   {
                    perror("kill"); 
                   }
           
         break;

         // sendto
          case EVENT_NETWORK_SEND :

            
            alert_high(event,"TRY TO SEND SOMETHING ");
                  if (kill(event->pid, SIGKILL) == -1)
                   {
                    perror("kill"); 
                   }
           
         break;


         default:
         break;


          }

    }
