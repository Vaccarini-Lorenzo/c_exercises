#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <time.h>

static inline void log_timestamp(void)
{
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    fprintf(stderr, "%02d:%02d:%02d ",
            tm->tm_hour, tm->tm_min, tm->tm_sec);
}

#define LOG(...) do { \
    log_timestamp(); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
} while(0)

#endif
