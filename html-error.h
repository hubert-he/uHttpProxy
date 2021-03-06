#ifndef TINYPROXY_HTML_ERROR_H
#define TINYPROXY_HTML_ERROR_H

/* Forward declaration */
struct conn_s;

extern int add_new_errorpage (char *filepath, unsigned int errornum);
extern int send_http_error_message (struct conn_s *connptr);
extern int indicate_http_error (struct conn_s *connptr, int number,
                                const char *message, ...);
extern int add_error_variable (struct conn_s *connptr, const char *key,
                               const char *val);
extern int send_http_headers (struct conn_s *connptr, int code,
                              const char *message);
extern int add_standard_vars (struct conn_s *connptr);

#endif /* !TINYPROXY_HTML_ERROR_H */
