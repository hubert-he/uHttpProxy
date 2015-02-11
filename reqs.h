/*
**  Author: hubert_he@realsil.com.cn
**  3rdParty: tinyProxy: https://banu.com/tinyproxy/
** Http Proxy: asynchronous and non-block socket implementation
** 
*/
#ifndef _TINYPROXY_REQS_H_
#define _TINYPROXY_REQS_H_

#include "conns.h"
/*
 * Port constants for HTTP (80) and SSL (443)
 */
#define HTTP_PORT 80
#define HTTP_PORT_SSL 443


/*
 * This structure holds the information pulled from a URL request.
 */
struct request_s {
        char *method;
        char *protocol;

        char *host;
        uint16_t port;

        char *path;
};
struct conn_s* new_conn_s_struct(int fd);
void all_resource_clean();
int handle_connection_from_client(struct conn_s *connptr);
int handle_new_srv_connection(struct conn_s *connptr);
int handle_connection_from_server(struct conn_s *connptr);
int handle_relay_connection(int fd, struct conn_s *connptr);

#endif
