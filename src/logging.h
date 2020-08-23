/*
 * logging functions
 */
#ifndef _LOGGING_H_
#define _LOGGING_H_

#include <stdarg.h>

void log_error(const char *format, ...);
void log_msg(const char *format, ...);
void log_err_errno(const char *format, ...);

#endif
