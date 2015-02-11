/*
**  Author: hubert_he@realsil.com.cn
**  3rdParty: tinyProxy: https://banu.com/tinyproxy/
**  About FTP proxy: squid http://www.squid-cache.org/
** Http Proxy: asynchronous and non-block socket implementation
** 
*/

#ifndef TINYPROXY_CONNS_H
#define TINYPROXY_CONNS_H

#include "compatible.h"

#define FTP_CTRL_PORT 21
#define FTP_DATA_PORT 22

struct FtpStateData
{
	int ftp_sock_fd;
	char user[MAX_URL];
    char password[MAX_URL];
	ftp_state_t state;
	struct io_flag
	{
		uint8 io_errno;
		uint8 io_read;
		uint8 io_write;
		uint8 io_reserved2;
	} io;
	struct CtrlChannel{
        char buf[1024];
        size_t size;
        int replycode;
		struct conn_s *ctrl_conn;
    } ctrl;

    struct DataChannel{
        MemBuf *readBuf;
        char *host;
        unsigned short port;
        bool read_pending;
		struct conn_s *data_conn;
    } data;
	
};


int ftpStateStart(struct conn_s *connptr);


#endif
