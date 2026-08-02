#include "rules.h"
#include "alert.h"
#include <string.h>
#include <signal.h>



void check_rules(event *event){




    switch (event->type){
 
        // open
        case EVENT_FILE_OPEN:

         if (strcmp(event->syscall,"open")==0 &&(strcmp(event->path,"/etc/passwd")==0 ||
                                                strcmp(event->path,"/etc/shadow")==0 ) )
            {
               alert_high(event,"TRY TO OPEN FILE FOR PASSWORDS ");   
            
               if (kill(event->pid, SIGKILL) == -1)
                {
                  perror("kill");
                } 
           

           }
         break;

        // read 
        case EVENT_FILE_READ:

         if (strcmp(event->syscall,"read")==0 && (strcmp(event->path,"/etc/passwd")==0 ||
                                                 strcmp(event->path,"/etc/shadow")==0 ))
            {

              alert_high(event,"TRY TO READ PASSWORDS ");     
            
              if (kill(event->pid, SIGKILL) == -1)
                 {
                  perror("kill"); 
                  }
            }
         break;


         // fork 
         case     EVENT_PROCESS_FORK:
      
         if(strcmp(event->syscall,"fork")==0){
                 
            alert_high(event,"TRY TO CREATE ANOTHER PROCESS");
                   if (kill(event->pid, SIGKILL) == -1)
                   {
                    perror("kill"); 

                   }
            }   
         break ;


          // execve
         case     EVENT_PROCESS_EXEC:
      
          if(strcmp(event->syscall,"execve")==0){
            
            alert_high(event,"TRY TO CHANGE THE PROG MISSION");
                  if (kill(event->pid, SIGKILL) == -1)
                   {
                    perror("kill"); 
                   }
           }
         break;


         // CONNECT
         case     EVENT_NETWORK_CONNECT:
      
          if(strcmp(event->syscall,"connect")==0){
            
            alert_high(event,"TRY TO CONNECT WITH SOMEONE");
                  if (kill(event->pid, SIGKILL) == -1)
                   {
                    perror("kill"); 
                   }
           }
         break;

         // sendto
          case EVENT_NETWORK_SEND :

           if(strcmp(event->syscall,"SENDTO")==0){
            
            alert_high(event,"TRY TO SEND SOMETHING ");
                  if (kill(event->pid, SIGKILL) == -1)
                   {
                    perror("kill"); 
                   }
           }
         break;


         default:
         break;




    }
}