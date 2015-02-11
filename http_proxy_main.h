/*
**  Author: hubert_he@realsil.com.cn
**  3rdParty: tinyProxy: https://banu.com/tinyproxy/
** Http Proxy: asynchronous and non-block socket implementation
** 
*/
#ifndef __HTTP_PROXY_MAIN_H__
#define __HTTP_PROXY_MAIN_H__

#include "ccb.h"
#include "compatible.h"

#define HTTP_PROXY_CLIENT_DATA 0x20
#define HTTP_PROXY_REMOTE_DATA 0x21
#define HTTP_PROXY_CLIENT_CONN 0x22

#define HTTP_PROXY_TIME_OUT	0x23

#define SOCKET_STATUS_INITIAL 0x0

#define CLIENT_REQUEST_LINE 0x40
#define SERVER_CONNECTION	0x41
#define SERVER_PUSH_TO_CLIENT 0x42
#define CLIENT_WAIT_SERVER 0x43
#define CLIENT_TWO_WAYS_TRANSFER	0x44
#define SERVER_TWO_WAYS_TRANSFER 0x45
#define CLIENT_CLOSE_TRANSFER 0x46
#define SERVER_CLOSE_TRANSFER 0x47

#define HTTP_PROXY_CHECK_TIME 20   //  2s
#define HTTP_STANDARD_TIME_OUT 750 // 75s
#define HTTP_PROXY_TIMERID  0x01

#define NO_HTTP_PROXY_PACKET -234
#define PROXY_CLIENT_FD 1


#if 0
#define HTTP_PROXY_CLOSE 0x31
#define PULL_SERVER_CONTENT 0x32
#define PUSH_TO_CLIENT 0x33
#define RESPONSE_TO_SRV 0x34
#define SRV_CONN 0x35
#define CONNECT_CLOSE 0x36
#endif

#define HttpProxy_MaxFD 520

#define SOCKET_BUF_SIZE (1460*8)
#define SOCKET_BUF_SIZE_BIGGER (1460*16)

#define SOCKET_BUF_SIZE_BIG (1460*32)


typedef struct http_request_info
{
	struct http_request_info *next;
	int socketfd;
} http_request;

//hook-func: for FTP read/write.
typedef int (*FtpRWHandler)(void *rwData);

typedef struct Proxy_Ctrl_Block
{
	struct Proxy_Ctrl_Block *next; /* can be used by any task */
	unsigned char *datap;
	int command;
	int data0;
	FtpRWHandler ftp_read_handler;
	void *read_data;
	FtpRWHandler ftp_write_handler;
	void *write_data;
} proxyCCB;

typedef struct proxy_command
{
	uint16 command;
} http_proxy_cmd;

typedef int (*notify_func)(int);


extern struct conn_fd conn_fd_pool[HttpProxy_MaxFD];
extern int debug_info_level;

static int httpProxy_client_notify(int fd);
static int httpProxy_remote_notify(int fd);
static int httpProxy_listen_notify(int fd);
static void http_proxy_client_conn();
static void http_proxy_client_data(proxyCCB *ccb_ptr);
static void http_proxy_remote_data(proxyCCB *ccb_ptr);
static void http_proxy_timer_notify();
static void http_proxy_time_out();
static void freeProxyCCB(proxyCCB *ccbPtr);
static proxyCCB* GetProxyCCB();
notify_func http_proxy_notify_func(int selector);


#endif
