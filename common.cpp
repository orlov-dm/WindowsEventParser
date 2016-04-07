#include "common.h"
#include <windows.h>
#include <ctime>

time_t getTimeFromSystemTime(const SYSTEMTIME &st)
{
    std::tm tm;

    tm.tm_sec = st.wSecond;
    tm.tm_min = st.wMinute;
    tm.tm_hour = st.wHour;
    tm.tm_mday = st.wDay;
    tm.tm_mon = st.wMonth - 1;
    tm.tm_year = st.wYear - 1900;
    tm.tm_isdst = -1;

    return std::mktime(&tm);
}
