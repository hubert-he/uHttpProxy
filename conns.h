/*
**  Author: hubert_he@realsil.com.cn
**  3rdParty: tinyProxy: https://banu.com/tinyproxy/
** Http Proxy: asynchronous and non-block socket implementation
** 
*/

#ifndef TINYPROXY_CONNS_H
#define TINYPROXY_CONNS_H

#include "compatible.h"
#include "hashmap.h"

#define PROXY_PROTOCOL_HTTP 0x1
#define PROXY_PROTOCOL_FTP  0x2
/*
 * Connection Definition
 */
struct conn_s
{
    int client_fd;
    int server_fd;
#ifdef RELAY_MEM_CTRL
	struct RelayBuf  *cbuffer0;
	struct RelayBuf  *sbuffer0;
#else
    struct buffer_s *cbuffer;
    struct buffer_s *sbuffer;
#endif

    /* The request line (first line) from the client */
    char *request_line;

    /* Booleans */
    unsigned int connect_method;
    unsigned int show_stats;

    /*
     * This structure stores key -> value mappings for substitution
     * in the error HTML files.
     */
    uint16 cfd_send_failed;
	uint16 sfd_send_failed;
    hashmap_t error_variables;
	
    int error_number;
    char *error_string;

    /* A Content-Length value from the remote server */
    struct
    {
        long int server;
        long int client;
    } content_length;

    /*
     * Store the server's IP (for BindSame)
     */
    char *server_ip_addr;
    /*
     * Store the client's IP and hostname information
     */
    char *client_ip_addr;
    char *client_string_addr;

    /*
     * Store the incoming request's HTTP protocol.
     */
    struct
    {
        unsigned int major;
        unsigned int minor;
    } protocol;

#ifdef REVERSE_SUPPORT
    /*
     * Place to store the current per-connection reverse proxy path
     */
    char *reversepath;
#endif
    /*
     * Pointer to upstream proxy.
     */
     hashmap_t hashofheaders;
	struct request_s *request;
    struct upstream *upstream_proxy;
#ifdef CONFIG_HTTP_PROXY_FTP_SUPPORT
	struct FtpStateData *ftpFwd;
	int conn_protocol;
#endif
};

/*
 * Functions for the creation and destruction of a connection structure.
 */
extern struct conn_s *initialize_conn (int client_fd, const char *ipaddr,
                                       const char *string_addr,
                                       const char *sock_ipaddr);
extern void destroy_conn (struct conn_s *connptr);
extern void free_request_struct (struct request_s *request);

extern int ignoreErrno(int ierrno);

#endif
