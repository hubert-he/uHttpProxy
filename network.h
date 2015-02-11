/*
**  Author: hubert_he@realsil.com.cn
**  3rdParty: tinyProxy: https://banu.com/tinyproxy/
** Http Proxy: asynchronous and non-block socket implementation
** 
*/

#ifndef TINYPROXY_NETWORK_H
#define TINYPROXY_NETWORK_H

#ifdef PROXY_DEBUG_SOCKET_TIMEOUT
extern ssize_t safe_write (char *caller, int line, int fd, const char *buffer, size_t count);
extern int write_message (char *callser, int line, int fd, const char *fmt, ...);
#else
extern ssize_t safe_write (int fd, const char *buffer, size_t count);
extern int write_message (int fd, const char *fmt, ...);

#endif

#define SEGMENT_LEN (1460*8)
#define MAXIMUM_BUFFER_LENGTH (128 * 1024)

#ifdef RELAY_MEM_CTRL
extern unsigned char http_header_line_buf[SEGMENT_LEN];
#endif

extern ssize_t safe_read (int fd, char *buffer, size_t count);
extern ssize_t readline (int fd, char **whole_buffer);

//extern char *get_ip_string (struct sockaddr *sa, char *buf, size_t len);
extern int full_inet_pton (const char *ip, void *dst);

#endif
