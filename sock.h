/*
**  Author: hubert_he@realsil.com.cn
**  3rdParty: tinyProxy: https://banu.com/tinyproxy/
** Http Proxy: asynchronous and non-block socket implementation
** 
*/
#ifndef TINYPROXY_SOCK_H
#define TINYPROXY_SOCK_H

/* The IP length is set to 48, since IPv6 can be that long */
#define IP_LENGTH		48
#define HOSTNAME_LENGTH		1024

#define MAXLINE (1024 * 4)

extern int opensock (const char *host, int port, const char *bind_to, int *status);

extern int socket_nonblocking (int sock);
extern int socket_blocking (int sock);

extern int getsock_ip (int fd, char *ipaddr);
extern int getpeer_information (int fd, char *ipaddr, char *string_addr);

#endif
