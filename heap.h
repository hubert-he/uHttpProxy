#ifndef TINYPROXY_HEAP_H
#define TINYPROXY_HEAP_H
#include "compatible.h"
#include "global.h"

 //* The following is to allow for better memory checking.
 //#define HTTP_PROXY_DEBUG 1

#ifdef HTTP_PROXY_DEBUG

extern void *debugging_calloc (size_t nmemb, size_t size, const char *file,
                               unsigned long line);
extern void *debugging_malloc (size_t size, const char *file,
                               unsigned long line);
extern void debugging_free (void *ptr, const char *file, unsigned long line);
extern void *debugging_realloc (void *ptr, size_t size, const char *file,
                                unsigned long line);
extern char *debugging_strdup (const char *s, const char *file,
                               unsigned long line);

#define safecalloc(x, y) debugging_calloc(x, y, __FILE__, __LINE__)
#define safemalloc(x) debugging_malloc(x, __FILE__, __LINE__)
#define saferealloc(x, y) debugging_realloc(x, y, __FILE__, __LINE__)
#define safestrdup(x) debugging_strdup(x, __FILE__, __LINE__)
#define safefree(x) (debugging_free(x, __FILE__, __LINE__), *(&(x)) = NULL)

#else

#define safecalloc(x, y) calloc(x, y)
#define safemalloc(x) malloc(x)
#define saferealloc(x, y) realloc(x, y)
#define safefree(x) (free (x), *(&(x)) = NULL)
#define safestrdup(x) strdup(x)

#endif


#endif
