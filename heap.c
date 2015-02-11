/* Debugging versions of various heap related functions are combined
 * here.  The debugging versions include assertions and also print
 * (to standard error) the function called along with the amount
 * of memory allocated, and where the memory is pointing.  The
 * format of the log message is standardized.
 */

#include "assert.h"
#include "heap.h"
#include "text.h"

#ifdef HTTP_PROXY_DEBUG

#undef assert
#define assert(expr) if((expr) == FALSE) return NULL;

void *debugging_calloc (size_t nmemb, size_t size, const char *file,
                        unsigned long line)
{
        void *ptr;

        assert (nmemb > 0);
        assert (size > 0);

        ptr = xcalloc (nmemb, size);
#if 0
        fprintf (stderr, "{calloc: %p:%lu x %lu} %s:%lu\n", ptr,
                 (unsigned long) nmemb, (unsigned long) size, file, line);
#else
		xprintfk("{calloc: %p:%lu x %lu} %s:%lu\n", \
			ptr, (unsigned long) nmemb, (unsigned long) size, file, line);
#endif
        return ptr;
}

void *debugging_malloc (size_t size, const char *file, unsigned long line)
{
        void *ptr;

        assert (size > 0);

        ptr = xmalloc (size);
#if 0
        fprintf (stderr, "{malloc: %p:%lu} %s:%lu\n", ptr,
                 (unsigned long) size, file, line);
#else
		xprintfk("{malloc: %p:%lu} %s:%lu\n", \
			ptr, (unsigned long) size, file, line);
#endif
        return ptr;
}

void *debugging_realloc (void *ptr, size_t size, const char *file,
                         unsigned long line)
{
        void *newptr;

        assert (size > 0);

        newptr = xrealloc (ptr, size);
#if 0
        fprintf (stderr, "{realloc: %p -> %p:%lu} %s:%lu\n", ptr, newptr,
                 (unsigned long) size, file, line);
#else
		xprintfk("{realloc: %p -> %p:%lu} %s:%lu\n", \
			ptr, newptr, (unsigned long) size, file, line);
#endif
        return newptr;
}

void debugging_free (void *ptr, const char *file, unsigned long line)
{
#if 0
	fprintf (stderr, "{free: %p} %s:%lu\n", ptr, file, line);
#else
	xprintfk("{free: %p} %s:%lu\n", ptr, file, line);
#endif
        if (ptr != NULL)
                xfree (ptr);
        return;
}

char *debugging_strdup (const char *s, const char *file, unsigned long line)
{
        char *ptr;
        size_t len;

        assert (s != NULL);

        len = strlen (s) + 1;
        ptr = (char *) xmalloc (len);
        if (!ptr)
                return NULL;
        memcpy (ptr, s, len);
#if 0
        fprintf (stderr, "{strdup: %p:%lu} %s:%lu\n", ptr,
                 (unsigned long) len, file, line);
#else
	xprintfk("{strdup: %p:%lu} %s:%lu\n", ptr, (unsigned long) len, file, line);
#endif
        return ptr;
}
#undef assert
#endif /* !NDEBUG */


