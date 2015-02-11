/*
**  Author: hubert_he@realsil.com.cn
**  3rdParty: tinyProxy: https://banu.com/tinyproxy/
** Http Proxy: asynchronous and non-block socket implementation
** 
*/
#ifndef COMPATIBLE_H
#define COMPATIBLE_H

#include "datatype.h"

#define LOG_INFO   	0x01
#define LOG_DEBUG  	0x02
#define LOG_ERR     0x04
#define LOG_FTP_DEB 0x06
#define LOG_WARNING	0x08

#define LOG_CONN    0x10
#define LOG_CRIT    0x20
#define LOG_NOTICE  0x40
#define LOG_TIMER	0x80

#define LOG_SHOW_ALL 	0xFF/*LOG_INFO|LOG_DEBUG|LOG_ERR|LOG_WARNING*/

#define HTTP_PROXY_DEBUG_LEVEL_ENABLE 1

#define HTTP_PROXY_SOCKET_BUF_ENLARGE 1

#define RELAY_MEM_CTRL 1

#define MAXBUFFSIZE     ((size_t)(1024 * 96))   /* Max size of buffer */
#define MAX_IDLE_TIME   (60 * 10)       /* 10 minutes of no activity */
/*
typedef unsigned int size_t;
typedef long ssize_t;
*/

#define PROXY_WAIT_MSG 255


#define NULL 0

#define PACKAGE "RTK-Proxy"
#define VERSION "1.0"
#define PACKAGE_NAME "RTK-Proxy"
extern uint32 mem_frag_cnt;
extern uint32 free_mem_frag_cnt;
extern uint32 relay_mem_frag;
extern uint32 free_relay_mem_frag;
struct conn_fd
{
	int fd;
	int status;
	struct conn_s *conn_ptr;
	unsigned short tick;
};

#define PROXYDEBUG xprintfk

#define HTTP_PROXY_ASSERT(x, y, ...) \
	do{ \
		if(!(x)) { \
			PROXYDEBUG(y); \
			return __VA_ARGS__; \
		} \
	} while(0) \


#ifdef HTTP_PROXY_DEBUG_LEVEL_ENABLE
extern int debug_info_level;
#endif

#define PROXY_DEBUG_SOCKET_TIMEOUT 1

#define log_message(Level, args...) proxy_log_message(__FUNCTION__, __LINE__, Level, args)

#endif
