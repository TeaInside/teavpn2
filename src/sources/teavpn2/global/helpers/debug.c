
#include <stdio.h>
#include <stdarg.h>
#include <teavpn2/global/helpers/debug.h>


void __pr_error(const char *fmt, ...)
{
	va_list vl;
	va_start(vl, fmt);
	printf("Error: ");
	vprintf(fmt, vl);
	va_end(vl);
	putchar(10);
}
