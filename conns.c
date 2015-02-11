/*
**  Author: hubert_he@realsil.com.cn
**  3rdParty: tinyProxy: https://banu.com/tinyproxy/
** Http Proxy: asynchronous and non-block socket implementation
**
** Create and free the connection structure. One day there could be
 * other connection related tasks put here, but for now the header
 * file and this file are only used for create/free functions and the
 * connection structure definition.
 */

#include "buffer.h"
#include "conns.h"
#include "heap.h"
#include "stats.h"
#include "reqs.h"

#include "errno.h"


/*
 * Free all the memory allocated in a request.
 */
void free_request_struct (struct request_s *request)
{
    if (!request)
        return;
    if(request->method)
        safefree (request->method);
    if(request->protocol)
        safefree (request->protocol);

    if (request->host)
        safefree (request->host);
    if (request->path)
        safefree (request->path);

    safefree (request);
}


struct conn_s *initialize_conn (int client_fd, const char *ipaddr,
                                const char *string_addr,
                                const char *sock_ipaddr)
{
    struct conn_s *connptr;
    HTTP_PROXY_ASSERT(client_fd >= 0, "initialize_conn: client_fd < 0\n", NULL);
    /*
     * Allocate the space for the conn_s structure itself.
     */
    connptr = (struct conn_s *) safemalloc (sizeof (struct conn_s));

    mem_frag_cnt++;
    if (!connptr)
        goto error_exit;

    connptr->client_fd = client_fd;
    connptr->server_fd = -1;
#ifdef CONFIG_HTTP_PROXY_FTP_SUPPORT
    connptr->conn_protocol = PROXY_PROTOCOL_HTTP;
    connptr->ftpFwd = NULL;
#endif
    /*
     * Allocate the memory for all the internal components
     */
#ifdef RELAY_MEM_CTRL
    connptr->cbuffer0 = NULL;
    connptr->sbuffer0 = NULL;
#else
    struct buffer_s *cbuffer, *sbuffer;
    cbuffer = new_buffer ();
    sbuffer = new_buffer ();

    if (!cbuffer || !sbuffer)
        goto error_exit;
    connptr->cbuffer = cbuffer;
    connptr->sbuffer = sbuffer;

#endif

    connptr->request_line = NULL;

    /* These store any error strings */
    connptr->error_variables = NULL;
    connptr->error_string = NULL;
    connptr->error_number = -1;
    connptr->cfd_send_failed = 0;
    connptr->sfd_send_failed = 0;

    connptr->connect_method = FALSE;
    connptr->show_stats = FALSE;

    connptr->protocol.major = connptr->protocol.minor = 0;

    /* There is _no_ content length initially */
    connptr->content_length.server = connptr->content_length.client = -1;

    connptr->server_ip_addr = (sock_ipaddr ?
                               safestrdup (sock_ipaddr) : NULL);
    connptr->client_ip_addr = safestrdup (ipaddr);
    connptr->client_string_addr = safestrdup (string_addr);
    connptr->hashofheaders = NULL;
    connptr->request = NULL;
    connptr->upstream_proxy = NULL;
    update_stats (STAT_OPEN);

#ifdef REVERSE_SUPPORT
    connptr->reversepath = NULL;
#endif
    return connptr;

error_exit:
#ifndef RELAY_MEM_CTRL
    /*
     * If we got here, there was a problem allocating memory
     */
    if (cbuffer)
        delete_buffer (cbuffer);
    if (sbuffer)
        delete_buffer (sbuffer);
#endif
    return NULL;
}

void destroy_conn (struct conn_s *connptr)
{
    int ret = 0, ret0 = 0;
    HTTP_PROXY_ASSERT(connptr != NULL, "destroy_conn: connptr==NULL\n");
    if (connptr->client_fd > 0)
        if ((ret = s_close (connptr->client_fd)) < 0)
        {
            //   xprintfk("ERROR: ret = %d, cfd = %d, %s\n", \
            //          ret, connptr->client_fd, connptr->request_line);
            log_message (LOG_INFO, "Client (%d) close message:\n",
                         connptr->client_fd);
        }

    if (connptr->server_fd > 0)
        if ((ret0 = s_close (connptr->server_fd)) < 0)
        {
            //    xprintfk("ERROR: ret = %d, cfd = %d, %s\n", \
            //      ret, connptr->client_fd, connptr->request_line);
            log_message (LOG_INFO, "Server (%d) close message: \n",
                         connptr->server_fd);
        }
    /*
        xprintfk("ret = %d, ret0 = %d, cfd = %d, sfd = %d, %s:%s:%s\n", \
                    ret, ret0, connptr->client_fd, connptr->server_fd, \
                    (connptr->request->host)?(connptr->request->host):"NULL", \
                    (connptr->request->method)?(connptr->request->method):"NULL", \
                    (connptr->request->path)?(connptr->request->path): "NULL");
    */
#ifdef RELAY_MEM_CTRL
    if (connptr->cbuffer0)
    {
        xfree (connptr->cbuffer0);
        free_relay_mem_frag++;
    }
    if (connptr->sbuffer0)
    {
        xfree (connptr->sbuffer0);
        free_relay_mem_frag++;
    }
#else
    if (connptr->cbuffer)
        delete_buffer (connptr->cbuffer);
    if (connptr->sbuffer)
        delete_buffer (connptr->sbuffer);
#endif
#ifndef RELAY_MEM_CTRL
    if (connptr->request_line)
        safefree (connptr->request_line);
#endif
    /*       if (connptr->error_variables)
                   hashmap_delete (connptr->error_variables);
    */
    if (connptr->error_string)
        safefree (connptr->error_string);

    if (connptr->server_ip_addr)
        safefree (connptr->server_ip_addr);
    if (connptr->client_ip_addr)
        safefree (connptr->client_ip_addr);
    if (connptr->client_string_addr)
        safefree (connptr->client_string_addr);
    if(connptr->hashofheaders)
        hashmap_delete (connptr->hashofheaders);
    if(connptr->request)
    {
        free_request_struct (connptr->request);
        connptr->request = NULL;
    }
#ifdef REVERSE_SUPPORT
    if (connptr->reversepath)
        safefree (connptr->reversepath);
#endif
    safefree (connptr);
    free_mem_frag_cnt++;
    update_stats (STAT_CLOSE);
}

int ignoreErrno(int ierrno)
{
    switch (ierrno)
    {

        case -EINPROGRESS:

        case -EWOULDBLOCK:

        case -EALREADY:

        case -EINTR:
			
        case -ERESTART:

            return TRUE;

        default:
            return FALSE;
    }
}


