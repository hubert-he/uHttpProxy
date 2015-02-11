#ifndef TINYPROXY_TEXT_H
#define TINYPROXY_TEXT_H
#include "stdarg.h"
#if 0
#ifndef HAVE_STRLCAT
extern size_t strlcat (char *dst, const char *src, size_t size);
#endif /* HAVE_STRLCAT */

#ifndef HAVE_STRLCPY
extern size_t strlcpy (char *dst, const char *src, size_t size);
#endif /* HAVE_STRLCPY */
#endif
extern ssize_t chomp (char *buffer, size_t length);

int	proxy_strcasecmp(const char *s, const char *t);	
int	proxy_strncasecmp(const char *s, const char *t, size_t n);

extern int vsnprintf(char *buffer, size_t bufsize,	const char *format, va_list ap);

#endif
