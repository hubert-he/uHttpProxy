/* This module handles the statistics for tinyproxy. There are only two
 * public API functions. The reason for the functions, rather than just a
 * external structure is that tinyproxy is now multi-threaded and we can
 * not allow more than one child to access the statistics at the same
 * time. This is prevented by a mutex. If there is a need for more
 * statistics in the future, just add to the structure, enum (in the header),
 * and the switch statement in update_stats().
 */

#include "compatible.h"

#include "heap.h"
#include "html-error.h"
#include "stats.h"
#include "utils.h"

struct stat_s
{
    unsigned long int num_reqs;
    unsigned long int num_badcons;
    unsigned long int num_open;
    unsigned long int num_refused;
    unsigned long int num_denied;
};

static struct stat_s *stats;

void init_stats (void)
{
    stats = (struct stat_s *) xmalloc (sizeof (struct stat_s));
    if (stats == NULL)
        return;

    memset (stats, 0, sizeof (struct stat_s));
}

/*
 * Display the statics of the tinyproxy server.
 */
int
showstats (struct conn_s *connptr)
{
    char *message_buffer;
    char opens[16], reqs[16], badconns[16], denied[16], refused[16];

    snprintf (opens, sizeof (opens), "%lu", stats->num_open);
    snprintf (reqs, sizeof (reqs), "%lu", stats->num_reqs);
    snprintf (badconns, sizeof (badconns), "%lu", stats->num_badcons);
    snprintf (denied, sizeof (denied), "%lu", stats->num_denied);
    snprintf (refused, sizeof (refused), "%lu", stats->num_refused);

    message_buffer = (char *) safemalloc (MAXBUFFSIZE);
    if (!message_buffer)
        return -1;

    snprintf
    (message_buffer, MAXBUFFSIZE,
     "<?xml version=\"1.0\" encoding=\"UTF-8\" ?>\n"
     "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN\" "
     "\"http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">\n"
     "<html>\n"
     "<head><title>%s version %s run-time statistics</title></head>\n"
     "<body>\n"
     "<h1>%s version %s run-time statistics</h1>\n"
     "<p>\n"
     "Number of open connections: %lu<br />\n"
     "Number of requests: %lu<br />\n"
     "Number of bad connections: %lu<br />\n"
     "Number of denied connections: %lu<br />\n"
     "Number of refused connections due to high load: %lu\n"
     "</p>\n"
     "<hr />\n"
     "<p><em>Generated by %s version %s.</em></p>\n" "</body>\n"
     "</html>\n",
     PACKAGE, VERSION, PACKAGE, VERSION,
     stats->num_open,
     stats->num_reqs,
     stats->num_badcons, stats->num_denied,
     stats->num_refused, PACKAGE, VERSION);

    if (send_http_message (connptr, 200, "OK",
                           message_buffer) < 0)
    {
        safefree (message_buffer);
        return -1;
    }

    safefree (message_buffer);
    return 0;
}

/*
 * Update the value of the statistics. The update_level is defined in
 * stats.h
 */
int update_stats (status_t update_level)
{
    switch (update_level)
    {
        case STAT_BADCONN:
            ++stats->num_badcons;
            break;
        case STAT_OPEN:
            ++stats->num_open;
            ++stats->num_reqs;
            break;
        case STAT_CLOSE:
            --stats->num_open;
            break;
        case STAT_REFUSE:
            ++stats->num_refused;
            break;
        case STAT_DENIED:
            ++stats->num_denied;
            break;
        default:
            return -1;
    }

    return 0;
}