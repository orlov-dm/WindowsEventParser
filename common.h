#ifndef COMMON_H
#define COMMON_H
//#include <windows.h>

struct _SYSTEMTIME;
#define SYSTEMTIME _SYSTEMTIME

typedef __int64 time_t;

time_t getTimeFromSystemTime(const SYSTEMTIME &st);

#endif // COMMON_H
