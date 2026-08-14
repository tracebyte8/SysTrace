#ifndef RULES_H
#define RULES_H
#include "event.h"
#include <stdio.h>
#include <syscall.h>
void check_rules(event *event);
void check_danger(pid_t pid,EventType type,char syscall[32],char path[256],int port);
#endif