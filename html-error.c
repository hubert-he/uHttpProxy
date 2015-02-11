/* This file contains source code for the handling and display of
 * HTML error pages with variable substitution.
 */

#include "buffer.h"
#include "conns.h"
#include "heap.h"
#include "html-error.h"
#include "network.h"
#include "utils.h"
#include "conf.h"
#include "stdarg.h"
#include "time.h"

/*
 * Add an error number -> filename mapping to the errorpages list.
 */
#define ERRORNUM_BUFSIZE 8      /* this is more than required */
#define ERRPAGES_BUCKETCOUNT 16

int add_new_errorpage (char *filepath, unsigned int errornum)
{
        char errornbuf[ERRORNUM_BUFSIZE];

        config.errorpages = hashmap_create (ERRPAGES_BUCKETCOUNT);
        if (!config.errorpages)
                return (-1);

        snprintf (errornbuf, ERRORNUM_BUFSIZE, "%u", errornum);

        if (hashmap_insert (config.errorpages, errornbuf,
                            filepath, strlen (filepath) + 1) < 0)
                return (-1);

        return (0);
}

/*
 * Get the file appropriate for a given error.
 */
static char *get_html_file (unsigned int errornum)
{
        hashmap_iter result_iter;
        char errornbuf[ERRORNUM_BUFSIZE];
        char *key;
        static char *val;

        assert (errornum >= 100 && errornum < 1000);

        if (!config.errorpages)
                return (config.errorpage_undef);

        snprintf (errornbuf, ERRORNUM_BUFSIZE, "%u", errornum);

        result_iter = hashmap_find (config.errorpages, errornbuf);

        if (hashmap_is_end (config.errorpages, result_iter))
                return (config.errorpage_undef);

        if (hashmap_return_entry (config.errorpages, result_iter,
                                  &key, (void **) &val) < 0)
                return (config.errorpage_undef);

        return (val);
}

/*
 * Look up the value for a variable.
 */
static char *lookup_variable (struct conn_s *connptr, const char *varname)
{
        hashmap_iter result_iter;
        char *key;
        static char *data;

        result_iter = hashmap_find (connptr->error_variables, varname);

        if (hashmap_is_end (connptr->error_variables, result_iter))
                return (NULL);

        if (hashmap_return_entry (connptr->error_variables, result_iter,
                                  &key, (void **) &data) < 0)
                return (NULL);

        return (data);
}

int send_http_headers (struct conn_s *connptr, int code, const char *message)
{
        const char *headers =
            "HTTP/1.0 %d %s\r\n"
            "Server: %s/%s\r\n"
            "Content-Type: text/html\r\n" "Connection: close\r\n" "\r\n";
#ifdef PROXY_DEBUG_SOCKET_TIMEOUT
	return (write_message (__FUNCTION__, __LINE__, connptr->client_fd, headers,
                               code, message, PACKAGE, VERSION));
#else
        return (write_message (connptr->client_fd, headers,
                               code, message, PACKAGE, VERSION));
#endif
}

/*
 * Display an error to the client.
 */
int send_http_error_message (struct conn_s *connptr)
{
     log_message (LOG_INFO,"%s:%d\n", __FUNCTION__, __LINE__);
     return (0);
}

/*
 * Add a key -> value mapping for HTML file substitution.
 */

#define ERRVAR_BUCKETCOUNT 16

int
add_error_variable (struct conn_s *connptr, const char *key, const char *val)
{
        if (!connptr->error_variables)
                if (!
                    (connptr->error_variables =
                     hashmap_create (ERRVAR_BUCKETCOUNT)))
                        return (-1);

        return hashmap_insert (connptr->error_variables, key, val,
                               strlen (val) + 1);
}

#define ADD_VAR_RET(x, y)				   \
	do {                                               \
                if (y == NULL)                             \
                        break;                             \
		if (add_error_variable(connptr, x, y) < 0) \
			return -1;			   \
	} while (0)

/*
 * Set some standard variables used by all HTML pages
 */
int add_standard_vars (struct conn_s *connptr)
{
        char errnobuf[16];
        char timebuf[30];
        time_t global_time;

        snprintf (errnobuf, sizeof errnobuf, "%d", connptr->error_number);
        ADD_VAR_RET ("errno", errnobuf);

        ADD_VAR_RET ("cause", connptr->error_string);
        ADD_VAR_RET ("request", connptr->request_line);
        ADD_VAR_RET ("clientip", connptr->client_ip_addr);
        ADD_VAR_RET ("clienthost", connptr->client_string_addr);

        /* The following value parts are all non-NULL and will
         * trigger warnings in ADD_VAR_RET(), so we use
         * add_error_variable() directly.
         */

        global_time = proxy_time (NULL);
        strftime (timebuf, sizeof (timebuf), "%a, %d %b %Y %H:%M:%S GMT",
                  gmtime (&global_time));
        add_error_variable (connptr, "date", timebuf);

        add_error_variable (connptr, "website",
                            "https://banu.com/tinyproxy/");
        add_error_variable (connptr, "version", VERSION);
        add_error_variable (connptr, "package", PACKAGE);

        return (0);
}

/*
 * Add the error information to the conn structure.
 */
int
indicate_http_error (struct conn_s *connptr, int number,
                     const char *message, ...)
{
        va_list ap;
        char *key, *val;

        va_start (ap, message);

        while ((key = va_arg (ap, char *))) {
                val = va_arg (ap, char *);

                if (add_error_variable (connptr, key, val) == -1) {
                        va_end (ap);
                        return (-1);
                }
        }

        connptr->error_number = number;
        connptr->error_string = safestrdup (message);

        va_end (ap);

        return (add_standard_vars (connptr));
}
