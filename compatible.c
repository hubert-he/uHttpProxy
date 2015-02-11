/*
**  Author: hubert_he@realsil.com.cn
**  3rdParty: tinyProxy: https://banu.com/tinyproxy/
** Http Proxy: asynchronous and non-block socket implementation
** 
*/

#include "compatible.h"
#include "stdarg.h"
#include "reqs.h"

static const char *syslog_level[] =
{
    NULL,
    NULL,
    "CRITICAL",
    "ERROR",
    "WARNING",
    "NOTICE",
    "INFO",
    "DEBUG",
    "CONNECT"
};

#define TIME_LENGTH 16
#define STRING_LENGTH 800
uint32 mem_frag_cnt;
uint32 free_mem_frag_cnt;
uint32 relay_mem_frag;
uint32 free_relay_mem_frag;
void proxy_log_message (char *func, int line, int level, const char *fmt, ...)
{
    va_list va;
    int ret;

#ifdef HTTP_PROXY_DEBUG_LEVEL_ENABLE
    //if(debug_info_level != 1)
    //if(level != debug_info_level)
    //return;
    if(debug_info_level != LOG_FTP_DEB)
    	if(!debug_info_level || !(debug_info_level&level))
        	return;
#else
    if(!httpprxyXDebugState())
        return;
#endif
    if(func)
        xprintfk("%s: %d --> ", func, line);
    va_start(va, fmt);
    ret = xvprintfk(fmt, va);
    va_end(va);
    return;
}
#ifdef HTTP_PROXY_DEBUG_LEVEL_ENABLE
void dump_conn_request_info(int fd)
{
    extern struct conn_fd conn_fd_pool[1000];
    struct request_s *tmpReq = conn_fd_pool[fd].conn_ptr->request;
    if(tmpReq)
    {
        if(tmpReq->path && strlen(tmpReq->path) < 2048)
            xprintfk("%s: %d host = %s, port = %d, path = %s\n", \
                     __FUNCTION__, __LINE__, tmpReq->host, tmpReq->port, tmpReq->path);
        else
            xprintfk("%s: %d host = %s, port = %d\n", \
                     __FUNCTION__, __LINE__, tmpReq->host, tmpReq->port);
    }
}
#endif
