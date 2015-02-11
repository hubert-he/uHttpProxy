/* Misc. routines which are used by the various functions to handle strings
 * and memory allocation and pretty much anything else we can think of. Also,
 * the load cutoff routine is in here. Could not think of a better place for
 * it, so it's in here.
 */

#include "compatible.h"

#include "conns.h"
#include "heap.h"
#include "http-message.h"
#include "utils.h"

/*
 * Build the data for a complete HTTP & HTML message for the client.  only for showstats()
 */
int
send_http_message (struct conn_s *connptr, int http_code,
                   const char *error_title, const char *message)
{
    static const char *headers[] =
    {
        "Server: " PACKAGE "/" VERSION,
        "Content-type: text/html",
        "Connection: close"
    };

    http_message_t msg;

    msg = http_message_create (http_code, error_title);
    if (msg == NULL)
        return -1;

    http_message_add_headers (msg, headers, 3);
    http_message_set_body (msg, message, strlen (message));
    if(http_message_send (msg, connptr->client_fd) < 0)
		return -1;
    http_message_destroy (msg);

    return 0;
}

