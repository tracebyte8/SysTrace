#ifndef ALERT_H
#define ALERT_H
#include <stdio.h>
#include "event.h"




void open_alert(void);
  void write_alert(const char *pathname);
    void alert_high(event *event,const char *details);
     void close_alert(void);

#endif