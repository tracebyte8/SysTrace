#ifndef FD_TABLES_H
#define FD_TABLES_H

#include <sys/types.h>
#include <sys/user.h>
  void get_file_entry(pid_t pid, struct user_regs_struct *regs, char filename[100]); 
  void get_fd_exit(struct user_regs_struct *regs);
  char *search_fd(int fd);
  void remove_fd(int fd);
  void get_socket_entry(void);
#endif