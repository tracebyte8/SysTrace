#ifndef TRACER_H
#define TRACER_H

extern int file;
extern int process;
extern int network;
extern int forkit;
extern int openit;
extern int readit;
extern int excve;
extern int connectit;
extern int memory;
extern int chmod;
extern int killit;
void trace(char *program);

#endif