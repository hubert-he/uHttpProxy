#ifndef TINYPROXY_UTILS_H
#define TINYPROXY_UTILS_H

/*
 * Forward declaration.
 */
struct conn_s;

extern int send_http_message (struct conn_s *connptr, int http_code,
                              const char *error_title, const char *message);

#endif
