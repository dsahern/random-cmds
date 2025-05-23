/*
 * logging functions
 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "logging.h"

unsigned int verbose;

void log_error(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}

void log_msg(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stdout, format, args);
	va_end(args);
}

void log_err_errno(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	fprintf(stderr, ": %d: %s\n", errno, strerror(errno));
}

void log_debug(const char *format, ...)
{
	va_list args;

	if (verbose) {
		va_start(args, format);
		vfprintf(stdout, format, args);
		va_end(args);
	}
}
