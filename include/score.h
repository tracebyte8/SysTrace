#ifndef SCORE_H
#define SCORE_H
#include "stat.h"
int compute_risk_score(syscall_stat *stats);
int compute_main_risk_score(void);
#endif