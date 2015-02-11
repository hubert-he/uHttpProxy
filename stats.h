#ifndef _TINYPROXY_STATS_H_
#define _TINYPROXY_STATS_H_

#include "conns.h"

/*
 * Various logable statistics
 */
typedef enum {
        STAT_BADCONN,           /* bad connection, for unknown reason */
        STAT_OPEN,              /* connection opened */
        STAT_CLOSE,             /* connection closed */
        STAT_REFUSE,            /* connection refused (to outside world) */
        STAT_DENIED             /* connection denied to tinyproxy itself */
} status_t;

/*
 * Public API to the statistics for tinyproxy
 */
extern void init_stats (void);
extern int showstats (struct conn_s *connptr);
extern int update_stats (status_t update_level);

#endif
