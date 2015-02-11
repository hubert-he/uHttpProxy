/*
**  Author: hubert_he@realsil.com.cn
**  3rdParty: tinyProxy: https://banu.com/tinyproxy/
** Http Proxy: asynchronous and non-block socket implementation
**
**
*/
#include "global.h"
#include "http_proxy_main.h"
#include "ccb.h"
#include "phase2.h"
#include "stats.h"
#include "conns.h"
#include "reqs.h"

#ifdef HTTP_PROXY_DEBUG_LEVEL_ENABLE

#include "cli.h"
#include "object.h"

#endif


#define HTTP_PROXY_QUEUE_TOTAL 0x8000  // need buf : 512K

#define SEND_RETRY_CNT 1000

static OSKMAILBOX httpProxyQueue, *httpProxyQueuePtr;

//static OSKMAILBOX proxySocketQueue, *proxySocketQueuePtr;
OSKMAILBOX proxySocketQueue, *proxySocketQueuePtr;

static OSKTIMER httpProxyTimer;
static int httpProxySocket = -1;
static unsigned int httpProxyPort;

static struct sockaddr_in localAddrForHttpProxy;
static unsigned int httpProxySrvTaskUp = 0;
static int httpProxyConnNotify(int fd);
int handle_connection_from_server(struct conn_s *connptr);

struct conn_fd conn_fd_pool[HttpProxy_MaxFD];
static unsigned int max_conn_fd;


#ifdef HTTP_PROXY_DEBUG_LEVEL_ENABLE
int debug_info_level;
enum proxy_cmd_token
{
    TOKEN_NULL,
    TOKEN_HTTP_PROXY_START,
    TOKEN_HTTP_PROXY,
    TOKEN_DEBUG,
    TOKEN_HTTP_PROXY_ENABLE,
    TOKEN_HTTP_PROXY_DISABLE,
    TOKEN_HTTP_PROXY_ERROR,
    TOKEN_HTTP_PROXY_WARNING,
    TOKEN_HTTP_PROXY_FTPDEB,
    TOKEN_HTTP_PROXY_INFO,
    TOKEN_HTTP_PROXY_DEBUG,
    TOKEN_HTTP_PROXY_ALL,
    TOKEN_END
};
enum http_proxy_command
{
    COMMAND_NULL,
    COMMAND_PROXY_DEBUG_SET,
    COMMAND_END
};


TOKENTBL proxyTokenTbl[] =
{
    {TOKEN_NULL, "null"},
    {TOKEN_HTTP_PROXY, "proxy"},
    {TOKEN_DEBUG,"debug"},
    {TOKEN_HTTP_PROXY_ENABLE, "enable"},
    {TOKEN_HTTP_PROXY_DISABLE, "disable"},
    {TOKEN_HTTP_PROXY_ERROR, "error"},
    {TOKEN_HTTP_PROXY_WARNING, "warning"},
    {TOKEN_HTTP_PROXY_FTPDEB, "ftpdeb"},
    {TOKEN_HTTP_PROXY_INFO, "info"},
    {TOKEN_HTTP_PROXY_DEBUG, "debug"},
    {TOKEN_HTTP_PROXY_ALL, "all"},
    { 0, 0}
};

static BNF cfgHttpProxyTable[]=
{
    { TOKEN_DEBUG, L1, N2, ENDNO|COMMAND, COMMAND_PROXY_DEBUG_SET, 0, 0},
    { TOKEN_HTTP_PROXY_ENABLE, L2,N3, ENDNO|OBJECT, OBJENABLE, 0, 0},
    { TOKEN_HTTP_PROXY_DISABLE,L2,N0, END|OBJECT, OBJDISABLE, 0, 0},
    { TOKEN_HTTP_PROXY_ERROR, L3, N3, END|OBJECT, OBJONE, (BNFCALLBACK)LOG_ERR, "error" },
    { TOKEN_HTTP_PROXY_WARNING, L3, N3, END|OBJECT, OBJONE, (BNFCALLBACK)LOG_WARNING, "warning" },
    { TOKEN_HTTP_PROXY_INFO, L3, N3, END|OBJECT, OBJONE, (BNFCALLBACK)LOG_INFO, "info" },
    { TOKEN_HTTP_PROXY_DEBUG, L3, N3, END|OBJECT, OBJONE, (BNFCALLBACK)LOG_DEBUG, "debug" },
    { TOKEN_HTTP_PROXY_FTPDEB, L3, N3, END|OBJECT, OBJONE, (BNFCALLBACK)LOG_FTP_DEB, "ftpdeb" },
    { TOKEN_HTTP_PROXY_ALL, L3, N3, END|OBJECT, OBJONE, (BNFCALLBACK)LOG_SHOW_ALL, "all" },
    {   0, 0, 0, 0, 0, 0}
};

static BNF proxyTable =
{ TOKEN_HTTP_PROXY, L0, N1, TABLE, 0, (BNFCALLBACK) cfgHttpProxyTable, "proxy debug enable/disable"};

static void commandProxydebugSet(CMDATA *cmdata)
{
    if (cmdata->mode != DELETE_MODE)
    {
        if (isObjTypeExist( cmdata, OBJENABLE))
        {
            unsigned int mode, modemask, index;
            for ( modemask=0, index = 0; index < cmdata->nextindex; index++)
            {
                switch ( (uint32)cmdata->objtype[index])
                {
                    case OBJONE:
                        mode = (uint32) cmdata->object[index];
                        modemask |= mode;
                        break;
                }
            }
            debug_info_level = modemask;
        }
        else if( isObjTypeExist( cmdata, OBJDISABLE))
        {
            debug_info_level = 0;
        }
        xprintfk("commandProxydebugSet: debug_info_level=0x%x\n", debug_info_level);

    }
    else
    {
        xprintfk("unsupport no mode\n");
    }
    return;
}


static uint32 ProxyCommandExecute(CMDATA *  cmdata)
{
    switch (cmdata->command)
    {
        case COMMAND_PROXY_DEBUG_SET:
            commandProxydebugSet( cmdata);
            break;
        default:
            commandNotSupport(cmdata);
            break;
    }
}

#endif

void attachHttpProxyTask()
{
    extern void httpProxyMain( int argc, char *argv);
#define STACKSIZE 0x1000
    registerTask( "httpProxy ", (void *)httpProxyMain, STACKSIZE*5, 4, 0);

}

void getHttpProxySrvPort()
{
    // from config flash file
    httpProxyPort = 4423;
}
#if 1
int HttpProxySendBuf2Q(proxyCCB *ccbptr, OSKMAILBOX *httpProxyQ)
{
    if(sendMsgQ(httpProxyQ, (void**)&ccbptr, 0) != OSK_SUCCESS)
    {
        int fd=0;
        xprintfk("\033[0;32m ++%s %x %x fd = %d cmd = %d\n  \033[0m",
                 __FUNCTION__, httpProxyQ->msgqcnt, \
                 httpProxyQ->msgqmaxlen, fd, ccbptr->command);
        // try to recovery
        if(ccbptr->datap) memcpy((char *)&fd, ccbptr->datap, sizeof(int));
        if(httpProxyQ->msgqcnt >= httpProxyQ->msgqmaxlen)
        {
            if( fd ==httpProxySocket && ccbptr->command == HTTP_PROXY_CLIENT_CONN)
                xipCleanUpNewConnSocket(httpProxySocket, proxySocketQueue);
            else
                xipCleanUpNewDataSocket(fd, proxySocketQueue);
        }
        else
        {
            xprintfk("\033[0;32mHttpProxySendBuf2Q: Unknown sendMsgQ ERROR\033[0m\n");
        }
        freeProxyCCB(ccbptr);
        return FALSE;
    }
    return(TRUE);
}
#else
static uint32 MaxMsgCnt;
int HttpProxySendBuf2Q(CCB *ccbptr, OSKMAILBOX *httpProxyQ)
{
    sendMsgQ(httpProxyQ, (void**)&ccbptr, 1);
    MaxMsgCnt = (MaxMsgCnt < httpProxyQ->msgqcnt)?httpProxyQ->msgqcnt:MaxMsgCnt;
    return(TRUE);
}
#endif
static int httpProxyUp()
{
    int ret;
    int sockentBufLen = SOCKET_BUF_SIZE;//
    getHttpProxySrvPort();
    int nodelay_flag = 1;

    ret = xTcpInit(&httpProxySocket, httpProxyPort, &localAddrForHttpProxy);
    if(ret == 0)
    {
        setsockopt(httpProxySocket, SOL_SOCKET, SO_RCVBUF, (char*)&sockentBufLen, sizeof(int));
        sockentBufLen = SOCKET_BUF_SIZE_BIG;
        setsockopt(httpProxySocket, SOL_SOCKET, SO_SNDBUF, (char*)&sockentBufLen, sizeof(int));
        setsockopt(httpProxySocket, IPPROTO_TCP, TCP_NODELAY, (void *) &nodelay_flag, sizeof(nodelay_flag));
        xipMakeAsynSock(httpProxySocket, http_proxy_notify_func(HTTP_PROXY_CLIENT_CONN));
        xprintfk("\nHttp Proxy Server UP Successed\n");
    }
    else
        xprintfk("\nHttp Proxy Server UP Failed: ret = %d\n", ret);
    return ret;
}

static void httpProxyTaskInit()
{
    int status = 0;
    max_conn_fd = 0;
    proxySocketQueuePtr = &proxySocketQueue;
    taskMessageQueue( "ProxySOCKETQ", &proxySocketQueue,0);
    proxySocketQueue.msgqmaxlen = HTTP_PROXY_QUEUE_TOTAL;

    oskMbxCreation( &httpProxyQueue, "PROXYSRVQ");
    httpProxyQueue.msgqmaxlen = HTTP_PROXY_QUEUE_TOTAL;
    httpProxyQueuePtr = &httpProxyQueue;
    timerCreate ( &httpProxyTimer, "HTTP Proxy Timer", http_proxy_timer_notify, HTTP_PROXY_TIMERID, HTTP_PROXY_CHECK_TIME);
    status = httpProxyUp();
    if(status > 0) httpProxySrvTaskUp = 1;
    else httpProxySrvTaskUp = 0;

}

static void httpProxyStatInit()
{
    init_stats();
    load_http_proxy_config();
    /*
        xprintfk("conn_s: %d, CCB = %d, ", \
            sizeof (struct conn_s), sizeof(CCB));
    */
}

notify_func http_proxy_notify_func(int selector)
{
    switch(selector)
    {
        case HTTP_PROXY_CLIENT_CONN:
            return httpProxy_listen_notify;
        case HTTP_PROXY_CLIENT_DATA:
            return httpProxy_client_notify;
        case HTTP_PROXY_REMOTE_DATA:
            return httpProxy_remote_notify;
        default:
            return 0;
    }
}

static proxyCCB proxyCCBPool[HTTP_PROXY_QUEUE_TOTAL];
static unsigned int proxyCCBPoolIndex;
static unsigned int proxyCCBUsage;
static proxyCCB* GetProxyCCB()
{
    int ret = -1, i = 0;
    unsigned int loop_cnt = 0;
    if(proxyCCBPool[proxyCCBPoolIndex].command == 0)
    {
        ret = proxyCCBPoolIndex;
    }
    else
    {
        for(i = (proxyCCBPoolIndex + 1)%HTTP_PROXY_QUEUE_TOTAL, loop_cnt = 0;
            i !=  proxyCCBPoolIndex && loop_cnt < HTTP_PROXY_QUEUE_TOTAL; \
            i = (i+1)%HTTP_PROXY_QUEUE_TOTAL, loop_cnt++)
        {
            if(proxyCCBPool[i].command == 0)
            {
                ret = i;
                break;
            }
        }
    }
    if(ret == -1)
    {
        xprintfk("proxyCCBPool FULL: %x:%x\n", loop_cnt, proxyCCBPoolIndex);
        return NULL;
    }
    proxyCCBUsage++;
    proxyCCBPoolIndex = (ret + 1) % HTTP_PROXY_QUEUE_TOTAL;
    return proxyCCBPool + ret;
}
static void freeProxyCCB(proxyCCB *ccbPtr)
{
    HTTP_PROXY_ASSERT(ccbPtr, "freeProxyCCB: proxyCCB NULL!\n", 0);
    ccbPtr->command = 0;
    ccbPtr->data0 = 0;
    ccbPtr->datap = NULL;
    proxyCCBUsage--;
}
static proxyCCB * check_msg_OK(int fd, int cmd)
{
    proxyCCB *proxy_ccb_ptr0;
    proxy_ccb_ptr0 = GetProxyCCB();
    if(proxy_ccb_ptr0 == NULL)
    {
        if( fd ==httpProxySocket && cmd == HTTP_PROXY_CLIENT_CONN)
            xipCleanUpNewConnSocket(httpProxySocket, proxySocketQueue);
        else
            all_resource_clean(fd, conn_fd_pool[fd].conn_ptr);
    }
    return proxy_ccb_ptr0;
}
static int httpProxy_client_notify(int fd)
{
    proxyCCB *proxy_ccb_ptr;
    proxy_ccb_ptr = check_msg_OK(fd, HTTP_PROXY_CLIENT_DATA);
    HTTP_PROXY_ASSERT(proxy_ccb_ptr, "httpProxy_client_notify: There isn't avilable ccb!\n", 0);

    proxy_ccb_ptr->command = HTTP_PROXY_CLIENT_DATA; // 0x20
    proxy_ccb_ptr->data0 = fd;
//   memcpy(ccbptr->datap, &fd, 4);

    HttpProxySendBuf2Q(proxy_ccb_ptr, httpProxyQueuePtr);
    log_message (LOG_INFO, "%s:fd=%d command=%x\n",__FUNCTION__,fd, proxy_ccb_ptr->command);
    return 0;
}

static int httpProxy_remote_notify(int fd)
{
    proxyCCB *proxy_ccb_ptr;
    proxy_ccb_ptr = check_msg_OK(fd, HTTP_PROXY_REMOTE_DATA);
    HTTP_PROXY_ASSERT(proxy_ccb_ptr, "httpProxy_remote_notify: There isn't avilable ccb!\n", 0);
    if(fd == 0) return 0;
    proxy_ccb_ptr->command = HTTP_PROXY_REMOTE_DATA; // 0x21
    proxy_ccb_ptr->data0 = fd;
	
    HttpProxySendBuf2Q(proxy_ccb_ptr, httpProxyQueuePtr);
    log_message (LOG_INFO, "%s:fd=%d command=%x\n",__FUNCTION__,fd, proxy_ccb_ptr->command);
    return 0;
}

static proxyCCB * httpProxy_event_notify(int fd, int cmd, void * ftp_state)
{
	proxyCCB *proxy_ccb_ptr;
	proxy_ccb_ptr = check_msg_OK(fd, cmd);
	HTTP_PROXY_ASSERT(proxy_ccb_ptr, "httpProxy_listen_notify: There isn't avilable ccb!\n", 0);

	if(fd == 0) return 0;
    proxy_ccb_ptr->command = cmd; // 0x21
    proxy_ccb_ptr->data0 = fd;
	proxy_ccb_ptr->datap = ftp_state;
    HttpProxySendBuf2Q(proxy_ccb_ptr, httpProxyQueuePtr);
    log_message (LOG_INFO, "%s:fd=%d command=%x\n",__FUNCTION__,fd, proxy_ccb_ptr->command);
    return proxy_ccb_ptr;
}


static int httpProxy_listen_notify(int fd)
{
//    CCB *ccbptr;
    proxyCCB *proxy_ccb_ptr;

    if(fd == httpProxySocket)
    {
        proxy_ccb_ptr = check_msg_OK(fd, HTTP_PROXY_CLIENT_CONN);
        HTTP_PROXY_ASSERT(proxy_ccb_ptr, "httpProxy_listen_notify: There isn't avilable ccb!\n", 0);
        proxy_ccb_ptr->command = HTTP_PROXY_CLIENT_CONN;  // 0x22
        HttpProxySendBuf2Q(proxy_ccb_ptr, httpProxyQueuePtr);
        log_message (LOG_INFO, \
                     "fd=%d command=%x\n", fd, proxy_ccb_ptr->command);
    }
    else
    {
        log_message (LOG_INFO, \
                     "fd=%d command=%x\n", fd, conn_fd_pool[fd].status);
        httpProxy_client_notify(fd);
    }
    return 0;
}

static void http_proxy_client_conn()
{
    int clientfd = -1;
    int packagelen = 0;

    clientfd = accept(httpProxySocket, NULL, NULL);
    log_message (LOG_INFO, "HTTP_PROXY_CLIENT_CONN: clientfd = %d\n", clientfd);
    if(clientfd > 0)
    {
        if(clientfd > max_conn_fd)
            max_conn_fd = clientfd;
        if(conn_fd_pool[clientfd].status != 0)
            xprintfk("\033[0;32m fd = %d %x \033[0m\n", \
                     conn_fd_pool[clientfd].fd, conn_fd_pool[clientfd].status);
        conn_fd_pool[clientfd].status = CLIENT_REQUEST_LINE;

        xipMakeAsynSock(clientfd, http_proxy_notify_func(HTTP_PROXY_CLIENT_DATA));
    }
    else
        xprintfk("%s:%d accept-ret=%d\n", __FUNCTION__, __LINE__, clientfd);
}
static void check_ret_from_handle_connection(int curfd, int ret_value, int event)
{
    notify_func event_handler = http_proxy_notify_func(event);
    int tempfd = conn_fd_pool[curfd].fd;
#if HTTP_PROXY_SOCKET_BUF_ENLARGE
	int sock_send_buf_enlarge = SOCKET_BUF_SIZE_BIGGER;// 23K
	unsigned int bufSize = 0, bufSize_uint = sizeof(unsigned int);
#endif
    struct conn_s *tmp_conn = NULL;
    switch(ret_value)
    {
        case -EWOULDBLOCK:
            tmp_conn = conn_fd_pool[curfd].conn_ptr;
            log_message (LOG_DEBUG, \
                         "fd %d: EWOULDBLOCK\n", curfd);
			//if(getsockopt(int sid, int level, int optname, void * optval, int * optlen))
#if HTTP_PROXY_SOCKET_BUF_ENLARGE
			//xprintfk("%s: %d fd = %d\n", __FUNCTION__, __LINE__, curfd);
			getsockopt(curfd, SOL_SOCKET, SO_SNDBUF, &bufSize, (socklen_t *)&bufSize_uint);
			if(bufSize < SOCKET_BUF_SIZE_BIGGER)
			{
				//xprintfk("%s: %d %x fd = %d buffsize = %d\n", __FUNCTION__, __LINE__, event, curfd, bufSize);
				setsockopt(curfd, SOL_SOCKET, SO_SNDBUF, (char*)&sock_send_buf_enlarge, sizeof(int));
			}
#endif
            reschedule();
            if(event == HTTP_PROXY_CLIENT_DATA)
            {
            	tmp_conn->cfd_send_failed++;
            }
            if(event == HTTP_PROXY_REMOTE_DATA)
            {
            	tmp_conn->sfd_send_failed++;
            }
            if(tmp_conn->cfd_send_failed <= SEND_RETRY_CNT && \
				tmp_conn->sfd_send_failed <= SEND_RETRY_CNT)
            {
                event_handler(curfd);
                reschedule();
            }
            break;
        case -PROXY_WAIT_MSG:
            break;
        case 0:
            log_message (LOG_WARNING, \
                         "%s: CLIENT_TWO_WAYS_TRANSFER: will shutdown[WR] %d\n", \
                         __FUNCTION__, curfd);
            shutdown(curfd, SHUT_RD);
            shutdown(tempfd, SHUT_WR);
            if(event == HTTP_PROXY_CLIENT_DATA)
            {
                conn_fd_pool[curfd].status = CLIENT_CLOSE_TRANSFER;
                if(conn_fd_pool[tempfd].status == SERVER_CLOSE_TRANSFER)
                    if(conn_fd_pool[tempfd].conn_ptr)
                    {
                        log_message(LOG_WARNING, "%s:%d: NEED TO clean conn_s(%d,%d)\n", \
                                    __FUNCTION__, __LINE__, curfd, tempfd);
                        all_resource_clean(curfd, conn_fd_pool[tempfd].conn_ptr);
                    }
                    else
                        log_message(LOG_ERR, \
                                    "%s: %d: connptr = NULL curfd = %d otherfd = %d\n", \
                                    __FUNCTION__, __LINE__, curfd, tempfd);
            }
            if(event == HTTP_PROXY_REMOTE_DATA)
            {
                conn_fd_pool[curfd].status = SERVER_CLOSE_TRANSFER;
                if(conn_fd_pool[tempfd].status == CLIENT_CLOSE_TRANSFER)
                    if(conn_fd_pool[tempfd].conn_ptr)
                    {
                        log_message(LOG_WARNING, "%s:%d: NEED TO clean conn_s(%d,%d)\n", \
                                    __FUNCTION__, __LINE__, curfd, tempfd);
                        all_resource_clean(curfd, conn_fd_pool[tempfd].conn_ptr);
                    }
                    else
                        log_message(LOG_ERR, "%s: %d: connptr = NULL curfd = %d otherfd = %d\n", \
                                    __FUNCTION__, __LINE__, curfd, tempfd);
            }
            break;
        case -1:
            log_message(LOG_DEBUG, \
                        "recv Error: close socket: %d:%d\n", curfd, tempfd);
            all_resource_clean(curfd, conn_fd_pool[tempfd].conn_ptr);
            break;
        default:
            if(ret_value > 0)
            {
                tempfd = conn_fd_pool[curfd].fd;
                conn_fd_pool[curfd].tick = 0;
                conn_fd_pool[tempfd].tick = 0;
            }
            else
                xprintfk("%s:%d: Unknow error\n", __FUNCTION__, __LINE__);
    }
}
static void http_proxy_client_data(proxyCCB *ccb_ptr)
{
    int curfd = 0, ret = 0, tempfd = 0;
    struct conn_s* connPtr = NULL;
    curfd = ccb_ptr->data0;
//    curfd = *((int*)(ccb_ptr->datap));
    if(curfd <= 0) return;
    log_message (LOG_INFO, "%s: status=%x fd=%d\n", \
                 __FUNCTION__, conn_fd_pool[curfd].status, curfd);
    switch(conn_fd_pool[curfd].status)
    {
        case SOCKET_STATUS_INITIAL: // eat delayed message from mailbox
            break;
        case CLIENT_REQUEST_LINE: // 0x40
            if(conn_fd_pool[curfd].conn_ptr == NULL)
            {
                connPtr = new_conn_s_struct(curfd);
                if(connPtr == NULL)
                {
                    xprintfk("%s:%d: connptr malloc failed\n", \
                             __FUNCTION__, __LINE__);
                    return;
                }
                conn_fd_pool[curfd].conn_ptr = connPtr;
            }
            ret = handle_connection_from_client(conn_fd_pool[curfd].conn_ptr);
            if(ret >0 && ret > max_conn_fd) max_conn_fd = ret;
            break;
        case CLIENT_WAIT_SERVER: // 0x43
            // modem need remote server to response,so waiting...
            if(conn_fd_pool[curfd].conn_ptr->hashofheaders)
            {
            	hashmap_delete(conn_fd_pool[curfd].conn_ptr->hashofheaders);
            	conn_fd_pool[curfd].conn_ptr->hashofheaders = NULL;
            }
            break;
        case CLIENT_TWO_WAYS_TRANSFER: // 0x44
            tempfd = conn_fd_pool[curfd].fd;
#ifndef HTTP_PROXY_DEBUG_LEVEL_ENABLE
            if(conn_fd_pool[curfd].conn_ptr->hashofheaders)
            {
            	hashmap_delete(conn_fd_pool[curfd].conn_ptr->hashofheaders);
				conn_fd_pool[curfd].conn_ptr->hashofheaders = NULL;
            }
            if(conn_fd_pool[curfd].conn_ptr->request)
            {
            	free_request_struct (conn_fd_pool[curfd].conn_ptr->request);
				conn_fd_pool[curfd].conn_ptr->request = NULL;
            }
            conn_fd_pool[curfd].conn_ptr->hashofheaders = NULL;
            conn_fd_pool[curfd].conn_ptr->request = NULL;
#endif
#ifdef RELAY_MEM_CTRL
            ret = handle_relay_connection2(curfd, conn_fd_pool[curfd].conn_ptr);
#else
            ret = handle_relay_connection(curfd, conn_fd_pool[curfd].conn_ptr);
#endif
            check_ret_from_handle_connection(curfd, ret, HTTP_PROXY_CLIENT_DATA);
            break;
        case CLIENT_CLOSE_TRANSFER:
            tempfd = conn_fd_pool[curfd].fd;
            //shutdown(tempfd, SHUT_WR);
            if(conn_fd_pool[tempfd].status == SERVER_CLOSE_TRANSFER)
            {
                if(conn_fd_pool[tempfd].conn_ptr)
                {
                    all_resource_clean(curfd, conn_fd_pool[tempfd].conn_ptr);
                }
                else
                    log_message(LOG_ERR, "%s: %d: connptr = NULL curfd = %d otherfd = %d\n", \
                                __FUNCTION__, __LINE__, curfd, tempfd);
            }
            break;
        default:
            log_message (LOG_ERR, "%s:Unknown CMD status=%x fd=%d\n", \
                         __FUNCTION__,conn_fd_pool[curfd].status,curfd);
    }
}
static void http_proxy_remote_data(proxyCCB *ccb_ptr)
{
    int curfd = 0, ret = 0, tempfd = 0;
    curfd = ccb_ptr->data0;
    // curfd = *((int*)(ccb_ptr->datap));
    if(curfd <= 0) return;
    log_message (LOG_INFO, "%s: status=%x fd=%d\n", \
                 __FUNCTION__,conn_fd_pool[curfd].status,curfd);
    switch(conn_fd_pool[curfd].status)
    {
        case SOCKET_STATUS_INITIAL: // eat delayed message from mailbox
            break;
        case SERVER_CONNECTION: // 0x41
            ret = handle_new_srv_connection(conn_fd_pool[curfd].conn_ptr);
            if(ret < 0)
            {
                log_message(LOG_INFO, "%s:%d SERVER_CONNECTION ret = -1\n", \
                            __FUNCTION__, __LINE__);
                all_resource_clean(curfd, conn_fd_pool[tempfd].conn_ptr);
            }
            else
                conn_fd_pool[curfd].status = SERVER_PUSH_TO_CLIENT;
            break;
        case SERVER_PUSH_TO_CLIENT: // 0x42
            ret = handle_connection_from_server(conn_fd_pool[curfd].conn_ptr);
            log_message(LOG_INFO, "SERVER_PUSH_TO_CLIENT: ret = %d\n", ret);
            if(ret == -EAGAIN)
                break;
            tempfd = conn_fd_pool[curfd].fd;
            if(ret)
            {
                conn_fd_pool[curfd].status = SERVER_TWO_WAYS_TRANSFER;
                if(conn_fd_pool[tempfd].status == CLIENT_WAIT_SERVER)
                {
                    conn_fd_pool[tempfd].status = CLIENT_TWO_WAYS_TRANSFER;
                }
                else
                    log_message (LOG_ERR, \
                                 "%s:%d status=%x fd=%d\n", __FUNCTION__, __LINE__, \
                                 conn_fd_pool[tempfd].status, tempfd);
            }
            break;
        case SERVER_TWO_WAYS_TRANSFER: // 0x45
            tempfd = conn_fd_pool[curfd].fd;
#ifdef CONFIG_HTTP_PROXY_FTP_SUPPORT
			if(ccb_ptr->datap)
			{
				ret = handle_ftp_http_tunnel(ccb_ptr->datap);
				check_ret_from_handle_connection(curfd, ret, HTTP_PROXY_REMOTE_DATA);
				break;
			}
#endif

#ifdef RELAY_MEM_CTRL
            ret = handle_relay_connection2(curfd, conn_fd_pool[curfd].conn_ptr);
#else
            ret = handle_relay_connection(curfd, conn_fd_pool[curfd].conn_ptr);
#endif
			check_ret_from_handle_connection(curfd, ret, HTTP_PROXY_REMOTE_DATA);
            break;
        case SERVER_CLOSE_TRANSFER:
            log_message (LOG_ERR, "%s: status=%x fd=%d\n", \
                         __FUNCTION__,conn_fd_pool[curfd].status,curfd);
            tempfd = conn_fd_pool[curfd].fd;
            shutdown(tempfd, SHUT_WR);
            if(conn_fd_pool[tempfd].status == CLIENT_CLOSE_TRANSFER)
                if(conn_fd_pool[tempfd].conn_ptr)
                {
                    log_message(LOG_WARNING, "%s:%d: NEED TO clean conn_s(%d,%d)\n", \
                                __FUNCTION__, __LINE__, curfd, tempfd);
                    all_resource_clean(curfd, conn_fd_pool[tempfd].conn_ptr);
                }
                else
                    log_message(LOG_ERR, "%s: %d: connptr = NULL curfd = %d otherfd = %d\n", \
                                __FUNCTION__, __LINE__, curfd, tempfd);
            break;
        default:
            log_message (LOG_ERR, "%s: status=%x fd=%d\n", \
                         __FUNCTION__, conn_fd_pool[curfd].status,curfd);
    }
}
#define TIMER_CCB_DEFINE(name) static proxyCCB* name
#define TIMER_CCB_GET(name,A) \
        do{\
            name=GetProxyCCB();\
            if(!name)\
            {\
                xprintfk("%s:ERROR:can't get timer ccb!!\n",__FUNCTION__);\
            }else\
                name->command = A;\
        }while(0)
#define TIMER_CCB_SENDMSG(name,queue,A) \
        do{\
            name=GetProxyCCB();\
            if(name){\
                name->command=A;\
                if((status = sendMsgQ(queue, (void**)&name, 1))!=OSK_SUCCESS)\
                    freeBuf(name);\
            }\
        }while(0)
#define TIMER_CCB_FREE(name) freeProxyCCB(name)

static void http_proxy_timer_notify()
{
    int status = OSK_FAIL;
    TIMER_CCB_DEFINE(timerccb);
    TIMER_CCB_SENDMSG(timerccb, httpProxyQueuePtr, HTTP_PROXY_TIME_OUT);
    if (status != OSK_SUCCESS)
        log_message(LOG_ERR, "%s:%d: send HTTP_PROXY_TIME_OUT Failed\n", \
                    __FUNCTION__, __LINE__);
}

static void http_proxy_time_out()
{
    int index;
    int will_max_fd = 0;
    struct conn_s *tmpconn = NULL;
    struct request_s *tmpreq = NULL;

    log_message(LOG_INFO, "max_conn_fd = %d\n", max_conn_fd);
    for(index = 0; index <= max_conn_fd; index++)
    {
        tmpconn = conn_fd_pool[index].conn_ptr;
        if(tmpconn) tmpreq = tmpconn->request;
        else        tmpreq = NULL;
        if(conn_fd_pool[index].tick <= HTTP_PROXY_CHECK_TIME)
        {
            if(conn_fd_pool[index].status != SOCKET_STATUS_INITIAL)
            { 
#if 1
            	if(conn_fd_pool[index].status == CLIENT_TWO_WAYS_TRANSFER && \
					tmpconn->cfd_send_failed >= SEND_RETRY_CNT)
					httpProxy_client_notify(index);
				else if(conn_fd_pool[index].status == SERVER_TWO_WAYS_TRANSFER && \
					tmpconn->sfd_send_failed >= SEND_RETRY_CNT)
					httpProxy_remote_notify(index);
#endif
            	conn_fd_pool[index].tick += HTTP_PROXY_CHECK_TIME;
            }
            continue;
        }
        if(conn_fd_pool[index].status)
            will_max_fd = (will_max_fd < index) ? index : will_max_fd;
        switch(conn_fd_pool[index].status)
        {
            case SERVER_CONNECTION:
                if(conn_fd_pool[index].tick < HTTP_STANDARD_TIME_OUT)
                {
                    conn_fd_pool[index].tick += HTTP_PROXY_CHECK_TIME;
                }
                else
                {
                    if(tmpreq)
                        log_message(LOG_INFO, \
                                    "SERVER_CONNECTION: srv = %d cli= %d tick:%d : %s %s %s\n", \
                                    index, conn_fd_pool[index].fd, conn_fd_pool[index].tick, \
                                    tmpreq->method, tmpreq->host, tmpreq->path);
                    all_resource_clean(index, conn_fd_pool[index].conn_ptr);
                }
                break;
            case CLIENT_REQUEST_LINE:
                if(conn_fd_pool[index].tick <= (4*HTTP_PROXY_CHECK_TIME))
                {
                    conn_fd_pool[index].tick += HTTP_PROXY_CHECK_TIME;
                    //  httpProxy_client_notify(index);
                }
                else
                {
                    log_message(LOG_TIMER, "CLIENT_REQUEST_LINE Time CTRL[Timeout=30 sec]\n");
                    all_resource_clean(index, conn_fd_pool[index].conn_ptr);
                }
                break;

            case SERVER_PUSH_TO_CLIENT:
                if(conn_fd_pool[index].tick <= (4*HTTP_PROXY_CHECK_TIME))
                {
                    conn_fd_pool[index].tick += HTTP_PROXY_CHECK_TIME;
                    httpProxy_remote_notify(index);
                }
                else
                {
                    log_message(LOG_TIMER, "SERVER_PUSH_TO_CLIENT Time CTRL[Timeout=30 sec]\n");
                    all_resource_clean(index, conn_fd_pool[index].conn_ptr);
                }
                //  httpProxy_remote_notify(index);
                break;
            case CLIENT_WAIT_SERVER:
                if(conn_fd_pool[index].tick <= (4*HTTP_PROXY_CHECK_TIME))
                {
                    conn_fd_pool[index].tick += HTTP_PROXY_CHECK_TIME;
                    httpProxy_client_notify(index);
                }
                else
                {
                    log_message(LOG_TIMER, "CLIENT_WAIT_SERVER Time CTRL[Timeout=30 sec]\n");
                    all_resource_clean(index, conn_fd_pool[index].conn_ptr);
                }
                //  httpProxy_client_notify(index);
                break;
            case CLIENT_TWO_WAYS_TRANSFER:
                if(conn_fd_pool[index].tick < HTTP_STANDARD_TIME_OUT)
                {
                    if(tmpreq)
                        log_message(LOG_TIMER, \
                                    "CLIENT_TWO_WAYS_TRANSFER: fds: %d:%d tick:%d : %s %s %s\n", \
                                    index, conn_fd_pool[index].fd, conn_fd_pool[index].tick, \
                                    tmpreq->method, tmpreq->host, tmpreq->path);
					if(tmpconn->cfd_send_failed >= SEND_RETRY_CNT)
						httpProxy_client_notify(index);
                    conn_fd_pool[index].tick += HTTP_PROXY_CHECK_TIME;
                }
                else
                {
                    // Time out, so collect socket, and clean all resource
                    if(tmpreq)
                        log_message(LOG_TIMER, \
                                    "CLIENT_TWO_WAYS_TRANSFER: fds: %d:%d tick:%d : %s %s %s\n", \
                                    index, conn_fd_pool[index].fd, conn_fd_pool[index].tick, \
                                    tmpreq->method, tmpreq->host, tmpreq->path);
                    conn_fd_pool[index].status = CLIENT_CLOSE_TRANSFER;
                    //all_resource_clean(curfd, conn_fd_pool[tempfd].conn_ptr);
                }
                httpProxy_client_notify(index);

                break;
            case SERVER_TWO_WAYS_TRANSFER:
                if(conn_fd_pool[index].tick < HTTP_STANDARD_TIME_OUT)
                {
                	if(tmpconn->sfd_send_failed >= SEND_RETRY_CNT)
						httpProxy_remote_notify(index);
                    conn_fd_pool[index].tick += HTTP_PROXY_CHECK_TIME;
                }
                else
                {
                    // Time out, so collect socket, and clean all resource
                    //all_resource_clean(index, conn_fd_pool[tempfd].conn_ptr);
                    conn_fd_pool[index].status = SERVER_CLOSE_TRANSFER;
                }
                httpProxy_remote_notify(index);
                break;
            default:
                break;
        }
    }
    max_conn_fd = will_max_fd;
    timerReset (&httpProxyTimer, http_proxy_timer_notify, HTTP_PROXY_CHECK_TIME);
}
static int httpprxyDebugId = 0;

int httpprxyDebugFlag()
{
    return(debugFlagEnable(httpprxyDebugId));
}

int httpprxyXDebugState()
{
    if (httpprxyDebugId == 0)
        return FALSE;

    if (debugFlagEnable(httpprxyDebugId)==FALSE)
        return FALSE;
    return TRUE;
}

__NON_VRAM void httpProxyMain(int argc0, char *argv0)
{
#define NICE_VALUE 160
    proxyCCB *ccbptr = 0;
    int status = 0;
    if (httpprxyDebugId==0)
        httpprxyDebugId= registerXDebugEntry("http-proxy", "debug HTTP Proxy");

    httpProxyTaskInit();
    httpProxyStatInit();
#ifdef  HTTP_PROXY_DEBUG_LEVEL_ENABLE
    registerBnf2RootTable( &proxyTable, &ProxyCommandExecute, proxyTokenTbl,0);
#endif
    reschedule();
    log_message (LOG_INFO, "Http Proxy Server UP\n");
    int http_proxy_process_count = NICE_VALUE;
    while(1)
    {
        http_proxy_process_count--;
        //status = waitMsgQ(httpProxyQueuePtr, (void**)&ccbptr);
        status = oskMbxGet(httpProxyQueuePtr, (void**)&ccbptr);
        if(status!=OSK_SUCCESS||!http_proxy_process_count)
        {
            http_proxy_process_count = NICE_VALUE;
            reschedule();
        }
        // status = getMsgQ(httpProxyQueuePtr, (void**)&ccbptr);
        if(ccbptr != 0 && status == OSK_SUCCESS)
        {
            switch(ccbptr->command)
            {
                case HTTP_PROXY_CLIENT_CONN:
                    http_proxy_client_conn();
                    break;
                case HTTP_PROXY_CLIENT_DATA:
                    http_proxy_client_data(ccbptr);
                    break;
                case HTTP_PROXY_REMOTE_DATA:
                    http_proxy_remote_data(ccbptr);
                    break;
                case HTTP_PROXY_TIME_OUT:
                    http_proxy_time_out();
                    break;
                default:
                    log_message (LOG_ERR, \
                                 "unknown ccbptr->command: %d\n", ccbptr->command);
            }
            freeProxyCCB(ccbptr);
        }
    }
}
