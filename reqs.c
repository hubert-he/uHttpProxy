/*
**  Author: hubert_he@realsil.com.cn
**  3rdParty: tinyProxy: https://banu.com/tinyproxy/
** Http Proxy: asynchronous and non-block socket implementation
**
** This is where all the work in tinyproxy is actually done. Incoming
 * connections have a new child created for them. The child then
 * processes the headers from the client, the response from the server,
 * and then relays the bytes between the two.
 */

#include "compatible.h"
#include "phase2.h"

#include "conf.h"
#include "buffer.h"
#include "conns.h"
#include "hashmap.h"
#include "heap.h"
#include "html-error.h"
#include "network.h"
#include "reqs.h"
#include "sock.h"
#include "stats.h"
#include "text.h"
#include "utils.h"
#include "vector.h"
#include "mytime.h"
#include "http_proxy_main.h"

#ifdef CONFIG_HTTP_PROXY_FTP_SUPPORT
#include "proxyFtp.h"
#endif

#include "nat.h"


#define atol(str)   strtol(str, (char **)NULL, 10)

static int httpProxyCloseConnection(int clientfd);
static char* get_Host(hashmap_t hashofheaders);
static char string_http_header[4096];
int len_tmp;

static char string_http_header[4096];
static char Request_Respond_header[1460];

/*
 * Maximum length of a HTTP line
 */
#define HTTP_LINE_LENGTH (MAXBUFFSIZE / 6)

/*
 * Macro to help test if the Upstream proxy supported is compiled in and
 * enabled.
 */
#ifdef UPSTREAM_SUPPORT
#  define UPSTREAM_CONFIGURED() (config.upstream_list != NULL)
#  define UPSTREAM_HOST(host) upstream_get(host, config.upstream_list)
#else
#  define UPSTREAM_CONFIGURED() (0)
#  define UPSTREAM_HOST(host) (NULL)
#endif

/*
 * Codify the test for the carriage return and new line characters.
 */
#define CHECK_CRLF(header, len)                                 \
  (((len) == 1 && header[0] == '\n') ||                         \
   ((len) == 2 && header[0] == '\r' && header[1] == '\n'))

/*
 * Codify the test for header fields folded over multiple lines. Must be writespace or tab
 */
#define CHECK_LWS(header, len)                                  \
  ((len) > 0 && (header[0] == ' ' || header[0] == '\t'))

/*
 * Read in the first line from the client (the request line for HTTP
 * connections. The request line is allocated from the heap, but it must
 * be freed in another function.
 */
static int read_request_line (struct conn_s *connptr)
{
    ssize_t len;
    int bug = 10;
retry:
#ifdef RELAY_MEM_CTRL
    connptr->request_line = &Request_Respond_header[0];
    len = readline2 (connptr->client_fd, &(connptr->request_line), 1);
#else
    len = readline (connptr->client_fd, &connptr->request_line);
#endif
    if (len <= 0)
    {
        if(len == -EAGAIN)
        {
            if(bug > 0)
            {
                bug--;
                goto retry;
            }
            else
                return -EAGAIN;
        }
        else
        {
            log_message (LOG_ERR,
                         "read_request_line: Client (file descriptor: %d) "
                         "closed socket before read.\n", connptr->client_fd);
            return -1;
        }
    }

    /*
     * Strip the new line and carriage return from the string.
     */
    if (chomp (connptr->request_line, len) == len)
    {
        /*
         * If the number of characters removed is the same as the
         * length then it was a blank line. Free the buffer and
         * try again (since we're looking for a request line.)
         */
#ifndef RELAY_MEM_CTRL
        safefree (connptr->request_line);
#endif
        goto retry;
    }

    log_message (LOG_CONN, "Request (file descriptor %d): %s\n",
                 connptr->client_fd, connptr->request_line);
    return 0;
}


/*
 * Take a host string and if there is a username/password part, strip
 * it off.
 * the url:  joe:jiespassword@www.joes-hard.com:80/seasonal/index-fall.htm
 */
static void strip_username_password (char *host)
{
    char *p;

    HTTP_PROXY_ASSERT((host) && (strlen (host) > 0), \
                      "strip_username_password: host == NULL");
    if ((p = strchr (host, '@')) == NULL)
        return;

    /*
     * Move the pointer past the "@" and then copy from that point
     * until the NUL to the beginning of the host buffer.
     */
    p++;
    while (*p)
        *host++ = *p++;
    *host = '\0';
}

/*
 * Take a host string and if there is a port part, strip
 * it off and set proper port variable i.e. for www.host.com:8001
 */
static int strip_return_port (char *host)
{
    char *ptr1;
    char *ptr2;
    int port;

    ptr1 = strrchr (host, ':');
    if (ptr1 == NULL)
        return 0;

    /* RFC2732: Format for Literal IPv6 Addresses in URL's
    ** http://[1080:0:0:0:8:800:200C:417A]/index.html  or  --> The below clauses will exact 417A]
    ** http://[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:80/index.html
    */
    /* Check for IPv6 style literals */
    ptr2 = strchr (ptr1, ']');
    if (ptr2 != NULL)
        return 0;

    *ptr1++ = '\0';

    if (xsscanf (ptr1, "%ld", &port) != 1)    /* one conversion required */
        return 0;
    return port;
}

/*
 * Pull the information out of the URL line.  This will handle both HTTP
 * and FTP (proxied) URLs. NOTE: http:// --> already be deleted
 */
static int extract_http_url (const char *url, struct request_s *request)
{
    char *p;
    int len;
    int port = 0;

    /* Split the URL on the slash to separate host from path */
    if(url)
        log_message (LOG_INFO, "url = %s\n", url);
    else
        goto ERROR_EXIT;
    p = strchr (url, '/');
    if (p != NULL)
    {
        len = p - url;
        request->host = (char *) safemalloc (len + 1);
        memcpy (request->host, url, len);
        request->host[len] = '\0';
        request->path = safestrdup (p);
    }
    else
    {
        request->host = safestrdup (url);
        request->path = safestrdup ("/");
    }

    if (!request->host || !request->path)
        goto ERROR_EXIT;

    /* Remove the username/password if they're present */
    strip_username_password (request->host);

    /* Find a proper port in www.site.com:8001 URLs */
    port = strip_return_port (request->host);
    request->port = (port != 0) ? port : HTTP_PORT;

    /* Remove any surrounding '[' and ']' from IPv6 literals */
    p = strrchr (request->host, ']');
    if (p && (*(request->host) == '['))
    {
        request->host++;
        *p = '\0';
    }

    return 0;

ERROR_EXIT:
    if (request->host)
        safefree (request->host);
    if (request->path)
        safefree (request->path);

    return -1;
}

/*
 * Extract the URL from a SSL connection.
 */
static int extract_ssl_url (const char *url, struct request_s *request)
{
    request->host = (char *) safemalloc (strlen (url) + 1);
    if (!request->host)
        return -1;

    if (sscanf (url, "%[^:]:%hu", request->host, &request->port) == 2) ;
    else if (sscanf (url, "%s", request->host) == 1)
        request->port = HTTP_PORT_SSL;
    else
    {
        log_message (LOG_ERR, "extract_ssl_url: Can't parse URL.");
        safefree (request->host);
        return -1;
    }

    /* Remove the username/password if they're present */
    strip_username_password (request->host);
    return 0;
}

/*
 * Create a connection for HTTP connections.
 */
static int
establish_http_connection (struct conn_s *connptr, struct request_s *request)
{
    char portbuff[7];
    char dst[sizeof(struct in6_addr)];

    /* Build a port string if it's not a standard port */
    if (request->port != HTTP_PORT && request->port != HTTP_PORT_SSL)
        snprintf (portbuff, 7, ":%u", request->port);
    else
        portbuff[0] = '\0';

    if (inet_pton(AF_INET6, request->host, dst) > 0)
    {
        /* host is an IPv6 address literal, so surround it with
         * [] */
#ifdef PROXY_DEBUG_SOCKET_TIMEOUT
        return write_message (__FUNCTION__, __LINE__,
                              connptr->server_fd,
                              "%s %s HTTP/1.0\r\n"
                              "Host: [%s]%s\r\n"
                              "Connection: close\r\n",
                              request->method, request->path,
                              request->host, portbuff);
#else
        return write_message (
                   connptr->server_fd,
                   "%s %s HTTP/1.0\r\n"
                   "Host: [%s]%s\r\n"
                   "Connection: close\r\n",
                   request->method, request->path,
                   request->host, portbuff);
#endif
    }
    else
    {
#ifdef PROXY_DEBUG_SOCKET_TIMEOUT
        return write_message (__FUNCTION__, __LINE__,
                              connptr->server_fd,
                              "%s %s HTTP/1.0\r\n"
                              "Host: %s%s\r\n"
                              "Connection: close\r\n",
                              request->method, request->path,
                              request->host, portbuff);
#else
        return write_message (
                   connptr->server_fd,
                   "%s %s HTTP/1.0\r\n"
                   "Host: %s%s\r\n"
                   "Connection: close\r\n",
                   request->method, request->path,
                   request->host, portbuff);
#endif
    }
    log_message(LOG_DEBUG, \
                "fd %d: \r\n"
                "%s %s HTTP/1.0\r\n"
                "Host: %s%s\r\n"
                "Connection: close\r\n",
                connptr->server_fd,
                request->method, request->path,
                request->host, portbuff);
}

/*
 * These two defines are for the SSL tunnelling.
 */
#define SSL_CONNECTION_RESPONSE "HTTP/1.0 200 Connection established"
#define PROXY_AGENT "Proxy-agent: " PACKAGE "/" VERSION

/*
 * Send the appropriate response to the client to establish a SSL
 * connection.
 */
static int send_ssl_response (struct conn_s *connptr)
{
#ifdef PROXY_DEBUG_SOCKET_TIMEOUT
    return write_message (__FUNCTION__, __LINE__,
                          connptr->client_fd,
                          "%s\r\n"
                          "%s\r\n"
                          "\r\n", SSL_CONNECTION_RESPONSE, PROXY_AGENT);
#else
    return write_message (connptr->client_fd,
                          "%s\r\n"
                          "%s\r\n"
                          "\r\n", SSL_CONNECTION_RESPONSE, PROXY_AGENT);
#endif
}

/*
 * Break the request line apart and figure out where to connect and
 * build a new request line. Finally connect to the remote server.
 */
static struct request_s *process_request (struct conn_s *connptr,
        hashmap_t hashofheaders)
{
    char *url;
    struct request_s *request;
    int ret = 0;
    size_t request_len;

    /* NULL out all the fields so frees don't cause segfaults. */
    request =
        (struct request_s *) safecalloc (1, sizeof (struct request_s));
    if (!request)
        return NULL;
    // fix mem free twice
    memset(request, 0, sizeof (struct request_s));
    request_len = strlen (connptr->request_line) + 1;

    request->method = (char *) safemalloc (request_len);
    url = (char *) safemalloc (request_len);
    request->protocol = (char *) safemalloc (request_len);

    if (!request->method || !url || !request->protocol)
    {
        goto fail;
    }

    ret = sscanf (connptr->request_line, "%[^ ] %[^ ] %[^ ]",
                  request->method, url, request->protocol);
    log_message(LOG_DEBUG, \
                "fds %d-%d: ret = %d, %s %s %s\n", \
                connptr->client_fd, connptr->server_fd, ret, \
                request->method, url, request->protocol);
    if (ret == 2 && !proxy_strcasecmp (request->method, "GET"))
    {
        request->protocol[0] = 0;

        /* Indicate that this is a HTTP/0.9 GET request */
        connptr->protocol.major = 0;
        connptr->protocol.minor = 9;
    }
    else if (ret == 3 && !proxy_strncasecmp (request->protocol, "HTTP/", 5))
    {
        /*
         * Break apart the protocol and update the connection
         * structure.
         */
        ret = sscanf (request->protocol + 5, "%u.%u",
                      &connptr->protocol.major,
                      &connptr->protocol.minor);

        /*
         * If the conversion doesn't succeed, drop down below and
         * send the error to the user.
         */
        if (ret != 2)
            goto BAD_REQUEST_ERROR;
    }
    else
    {
    BAD_REQUEST_ERROR:
        log_message (LOG_ERR,
                     "process_request: Bad Request on file descriptor %d",
                     connptr->client_fd);

        /*            indicate_http_error (connptr, 400, "Bad Request",
                                        "detail", "Request has an invalid format",
                                        "url", url, NULL);
            */
        goto fail;
    }

    if (!url)
    {
        log_message (LOG_ERR,
                     "process_request: Null URL on file descriptor %d",
                     connptr->client_fd);
        /*         indicate_http_error (connptr, 400, "Bad Request",
                                     "detail", "Request has an empty URL",
                                     "url", url, NULL); */
        goto fail;
    }
    if ((proxy_strncasecmp (url, "http://", 7) == 0)
        || (UPSTREAM_CONFIGURED () && proxy_strncasecmp (url, "ftp://", 6) == 0))
    {
        log_message (LOG_INFO, "%s: %d: %s\n", __FUNCTION__, __LINE__, url);
        char *skipped_type = strstr (url, "//") + 2;
        if (extract_http_url (skipped_type, request) < 0)
        {
            /*             indicate_http_error (connptr, 400, "Bad Request",
                                             "detail", "Could not parse URL",
                                             "url", url, NULL); */
            goto fail;
        }
    }
    else if (strcmp (request->method, "CONNECT") == 0)
    {
        if (extract_ssl_url (url, request) < 0)
        {
            /*             indicate_http_error (connptr, 400, "Bad Request",
                                             "detail", "Could not parse URL",
                                             "url", url, NULL); */
            goto fail;
        }

        /* Verify that the port in the CONNECT method is allowed */
        /*
        if (!check_allowed_connect_ports (request->port,
                                          config.connect_ports))
        {
            indicate_http_error (connptr, 403, "Access violation",
                                 "detail",
                                 "The CONNECT method not allowed "
                                 "with the port you tried to use.",
                                 "url", url, NULL);
            log_message (LOG_INFO,
                         "Refused CONNECT method on port %d",
                         request->port);
            goto fail;
        }
        */
        connptr->connect_method = TRUE;
    }
	else if((proxy_strncasecmp (url, "ftp://", 6) == 0))
	{
		log_message (LOG_INFO, "%s: %d: %s\n", __FUNCTION__, __LINE__, url);
#ifndef CONFIG_HTTP_PROXY_FTP_SUPPORT
		char *header = "HTTP/1.1 501 Not Implemented\r\nServer: PROXY_IN_MODEM\r\nContent-Type: text/html\r\nContent-Length: %d   \r\n\r\n";
		char * errFormat = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\"\n"
  			"\"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">\n"
			"<html xmlns=\"http://www.w3.org/1999/xhtml\">\n"
			"<head>\n"
			"<title>%d %s</title>\n"
			"<meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\" />\n"
			"</head>\n"
			"<body>\n"
			"<h1>Access Deny: %s</h1>\n"
			"<p>%s</p>\n"
			"<hr>\n"
			"<p>\n"
			"<em>Generated by %s</a> version %s.</em>\n"
			"</p>\n"
			"</body>\n"
			"</html>\n";
		write_message(__FUNCTION__, __LINE__, connptr->client_fd, header, strlen(errFormat));	
		write_message(__FUNCTION__, __LINE__, connptr->client_fd, errFormat, \
			500, "Not Implemented", "Not Implemented", "Unknown method or unsupported protocol.", PACKAGE, VERSION);
		
		goto fail;
#else
		connptr->conn_protocol = PROXY_PROTOCOL_FTP;
		request->path = safestrdup (url);
		request->port = FTP_CTRL_PORT;
		if(hashofheaders)
        {
            request->host = get_Host(hashofheaders);
            if(request->host == NULL)
            {
                xprintfk("ERROR: url = %s, but Host is NULL\n", url);
                goto fail;
            }
        }
        else
            goto fail;
		log_message (LOG_INFO, "%s: %d\n", __FUNCTION__, __LINE__);
    	safefree (url);
    	return request; 
#endif
	}
    else if(strcmp (request->method, "GET") == 0 || strcmp (request->method, "POST") == 0)
    {
        request->path = safestrdup (url);
        request->port = HTTP_PORT;
        if(hashofheaders)
        {
            request->host = get_Host(hashofheaders);
            if(request->host == NULL)
            {
                xprintfk("ERROR: url = %s, but Host is NULL\n", url);
                goto fail;
            }
        }
        else
            goto fail;
    }
    else
    {
        xprintfk(__FUNCTION__, __LINE__, "Unknown method (%s) or protocol (%s)", request->method, url);
        goto fail;
    }
    log_message (LOG_INFO, "%s: %d\n", __FUNCTION__, __LINE__);
    safefree (url);
    return request;  // if everything OK, return from here
fail:
    safefree (url);
    free_request_struct (request);
    return NULL;
}

/*
 * pull_client_data is used to pull across any client data (like in a
 * POST) which needs to be handled before an error can be reported, or
 * server headers can be processed.
 *  - rjkaes
 */
static int pull_client_data (struct conn_s *connptr, long int length)
{
    char *buffer;
    ssize_t len;

    buffer =
        (char *) safemalloc (min (MAXBUFFSIZE, (unsigned long int) length));
    mem_frag_cnt++;
    if (!buffer)
        return -1;

    do
    {
        len = safe_read (connptr->client_fd, buffer,
                         min (MAXBUFFSIZE, (unsigned long int) length));
        if (len <= 0)
            goto ERROR_EXIT;

        if (!connptr->error_variables)
        {
#ifdef PROXY_DEBUG_SOCKET_TIMEOUT
            if (safe_write (__FUNCTION__, __LINE__, connptr->server_fd, buffer, len) < 0)
#else
            if (safe_write (connptr->server_fd, buffer, len) < 0)
#endif
                goto ERROR_EXIT;
        }

        length -= len;
    }
    while (length > 0);

    /*
     * BUG FIX: Internet Explorer will leave two bytes (carriage
     * return and line feed) at the end of a POST message.  These
     * need to be eaten for tinyproxy to work correctly.
     */
    /* this CRCL does NOT include in the "Content Length"*/

    len = recv (connptr->client_fd, buffer, 2, MSG_PEEK);

    if (len < 0 && len != -EAGAIN)
        goto ERROR_EXIT;

    if ((len == 2) && CHECK_CRLF (buffer, len))
    {
        ssize_t ret;

//       ret = read (connptr->client_fd, buffer, 2);
        ret = recv(connptr->client_fd, buffer, 2, 0);
        if (ret == -1)
        {
            log_message(LOG_WARNING,
                        "Could not read two bytes from POST message");
        }
    }

    safefree (buffer);
    return 0;

ERROR_EXIT:
    safefree (buffer);
    return -1;
}

#ifdef XTINYPROXY_ENABLE
/*
 * Add the X-Tinyproxy header to the collection of headers being sent to
 * the server.
 *  -rjkaes
 */
static int add_xtinyproxy_header (struct conn_s *connptr)
{
    HTTP_PROXY_ASSERT((connptr && connptr->server_fd >= 0), \
                      "add_xtinyproxy_header: connptr == NULL\n", -1);
#ifdef PROXY_DEBUG_SOCKET_TIMEOUT
    return write_message (__FUNCTION__, __LINE__, connptr->server_fd,
                          "X-Tinyproxy: %s\r\n", connptr->client_ip_addr);
#else
    return write_message (connptr->server_fd,
                          "X-Tinyproxy: %s\r\n", connptr->client_ip_addr);
#endif
}
#endif /* XTINYPROXY */

/*
 * Take a complete header line and break it apart (into a key and the data.)
 * Now insert this information into the hashmap for the connection so it
 * can be retrieved and manipulated later.
 */
static int
add_header_to_connection (hashmap_t hashofheaders, char *header, size_t len)
{
    char *sep;

    /* Get rid of the new line and return at the end */
    len -= chomp (header, len);

    sep = strchr (header, ':');
    if (!sep)
        return -1;

    /* Blank out colons, spaces, and tabs. */
    while (*sep == ':' || *sep == ' ' || *sep == '\t')
        *sep++ = '\0';

    /* Calculate the new length of just the data */
    len -= sep - header - 1;

    return hashmap_insert (hashofheaders, header, sep, len);
}

unsigned char http_header_buf[SEGMENT_LEN];
#define CHK_THRESHHOLD 14 // check_threshhold
int check_out_proxy_packet(int packet_len)
{
    char *return_ptr = NULL;
    char* ret = 0;
    if(packet_len < CHK_THRESHHOLD)
        return 0;
    // check our http packet format
    char tmp = http_header_buf[CHK_THRESHHOLD];
    http_header_buf[CHK_THRESHHOLD] = '\0';
    log_message(LOG_INFO, "%s\n",http_header_buf);
    if(strstr(http_header_buf, "GET http://") || \
	   strstr(http_header_buf, "GET https://") || \
       strstr(http_header_buf, "POST http://") || \
       strstr(http_header_buf, "POST https://") || \
       strstr(http_header_buf, "GET ftp://"))
    {
        http_header_buf[CHK_THRESHHOLD] = tmp;
#if 0
        return_ptr = strstr (http_header_buf, "\r\n");
        if(return_ptr)
        {
            tmp = *return_ptr;
            *return_ptr = '\0';
            ret = strstr(http_header_buf, " http://");
            if(ret || strstr(http_header_buf, " https://"))
            {
                log_message(LOG_INFO, "%s\n", http_header_buf);
                *return_ptr = tmp;
                return 0;
            }
            else if(strstr(http_header_buf, " ftp://"))
            {
                log_message(LOG_INFO, "%s\n", http_header_buf);
                *return_ptr = tmp;
                return 0;
            }
            else
            {
                log_message(LOG_INFO, "NOT Proxy packet\n");
                return NO_HTTP_PROXY_PACKET;
            }
        }
#endif
        return 0;
    }
    else if(strstr(http_header_buf, "CONNECT "))
    {
        http_header_buf[CHK_THRESHHOLD] = tmp;
        return 0;
    }
    else
    {
        log_message(LOG_ERR, "check_out_proxy_packet: NOT HTTP packet\n");
        return NO_HTTP_PROXY_PACKET;
    }
}

static int check_http_headers_ok(int fd, int clientfd, int *recv_data_len)
{
    ssize_t ret = -1, header_length = 0;
    memset(http_header_buf, 0, SEGMENT_LEN);
    unsigned char *ptr = NULL;
    //Hubert_he-> NOTE: The MSG_PEEK Option, that is a packet be read but not out
    /*trancy_he 20130828 modify to get peer IP and port*/
#if 1
    struct sockaddr_storage peer;
    int iAddrLen = sizeof(peer);
    ret = recvfrom(fd, http_header_buf, SEGMENT_LEN, MSG_DONTWAIT|MSG_PEEK, (struct sockaddr *)&peer, &iAddrLen);
#else
    ret = recv (fd, http_header_buf, SEGMENT_LEN, MSG_PEEK);
#endif
    /*trancy_he 20130828 end*/
    if(ret <= 0)
    {
        log_message(LOG_DEBUG, \
                    "fd %d:recv_ret = %d\n", fd, ret);
        return ret;
    }
    if(recv_data_len) *recv_data_len = ret;
    if(clientfd == PROXY_CLIENT_FD)
    {
        ret = check_out_proxy_packet(ret);
#if 1
		if(MACRO_ENABLED(ipnp_httpproxy_enabled, directGetIPNPState()))
		{
			uint32 srcip,localip,destip;
			uint16 srcport,inItf,destport;
			Nat_T *n;
			int set_correct=0;
			HttpProxy *pTmpHttpProxy;
			srcip = ((struct sockaddr_in *)&peer)->sin_addr.s_addr;
			srcport = ((struct sockaddr_in *)&peer)->sin_port;
			inItf = getLanPort();
			localip = getPrimaryIpFromPif(inItf);
			n = natCacheFindByHttpProxy(IPPROTO_TCP,srcip,srcport,localip,4423,NAT_IG,NAT_OG,NATOW_NAT);
			if(n)
            {
                destip = n->ips[NAT_OL];
                destport = n->ports[NAT_OL];
                if (!list_empty(&httpProxyList))
                {
                    list_for_each_entry(pTmpHttpProxy, &httpProxyList, list)
                    {
                        if(pTmpHttpProxy->ips == srcip && pTmpHttpProxy->ipd == destip && pTmpHttpProxy->ipdport == destport)
                        {
                        	if(ret == NO_HTTP_PROXY_PACKET)
                        	{
	                            log_message(LOG_DEBUG, "del the wrong proxy(%s-->%s:%d), and del related nat entry!\n",getIPString(pTmpHttpProxy->ips),getIPString1(pTmpHttpProxy->ipd),pTmpHttpProxy->ipdport);
								list_del_init(&(pTmpHttpProxy->list));
	                            natDetach(n);
	                            break;
                        	}
							else
							{
								//xprintfk("the proxy is corrcet, then deny add proxy to list~!!!\n");
								pTmpHttpProxy->flag = 1;
								pTmpHttpProxy->state_flush = 1;
								set_correct = 1;
								break;
							}
                        }
                    }
                }
				if(set_correct)	//del others wrong proxy entry with the same src ip
				{
					HttpProxy *pHttpProxy;
					if (!list_empty(&httpProxyList))
					{
						list_for_each_entry(pHttpProxy, &httpProxyList, list)
						{
							if(pHttpProxy->ips == srcip && pHttpProxy->flag==0)
							{
								//xprintfk("nattick: delete the same src ip wrong proxy!!!!!!\n");
								list_del_init(&(pHttpProxy->list));
								break;
							}
						}
					}
				}
			}
		}
#else
        if(ret == NO_HTTP_PROXY_PACKET)
        {
/*trancy_he 20130828 start: do proxy list check and update*/
            if(MACRO_ENABLED(ipnp_httpproxy_enabled, directGetIPNPState()))
            {
                uint32 srcip = ((struct sockaddr_in *)&peer)->sin_addr.s_addr;
                uint16 srcport = ((struct sockaddr_in *)&peer)->sin_port;
                uint16 inItf = getLanPort();
                uint32 localip = getPrimaryIpFromPif(inItf);
                Nat_T *n;
                n = natCacheFindByHttpProxy(IPPROTO_TCP,srcip,srcport,localip,4423,NAT_IG,NAT_OG,NATOW_NAT);
                if(n)
                {
                    uint32 destip = n->ips[NAT_OL];
                    uint16 destport = n->ports[NAT_OL];
                    HttpProxy *pTmpHttpProxy;
                    if (!list_empty(&httpProxyList))
                    {
                        list_for_each_entry(pTmpHttpProxy, &httpProxyList, list)
                        {
                            if(pTmpHttpProxy->ips == srcip && pTmpHttpProxy->ipd == destip && pTmpHttpProxy->ipdport == destport)
                            {
                                log_message(LOG_DEBUG, "del the wrong proxy(%s-->%s:%d), and del related nat entry!\n",getIPString(pTmpHttpProxy->ips),getIPString1(pTmpHttpProxy->ipd),pTmpHttpProxy->ipdport);
                                list_del_init(&(pTmpHttpProxy->list));
                                natDetach(n);
                                break;
                            }
                        }
                    }
                }
            }
/*trancy_he 20130828 end*/
            return NO_HTTP_PROXY_PACKET;
        }
#endif
    }
    ptr = (char *) strstr (http_header_buf, "\r\n\r\n");
    if (ptr)
    {
        header_length = ptr - http_header_buf + 4;
#if 0
        if(debug_info_level == LOG_DEBUG || debug_info_level == LOG_SHOW_ALL)
        {
            xprintfk("check_http_headers_ok: %d: fd = %d header_length = %d\n", \
                     __LINE__, fd, header_length);
            //dumpBuffer(NULL, http_header_buf, header_length < 1025 ? header_length: 96);
            dumpBuffer(NULL, http_header_buf, 96);
        }
#endif
        return header_length;
    }
    else
    {
        log_message(LOG_DEBUG, \
                    "fd %d: PROXY_WAIT_MSG\n", fd);
#if 0
        if(debug_info_level == LOG_DEBUG || debug_info_level == LOG_SHOW_ALL)
        {
            xprintfk("check_http_headers_ok: %d: fd = %d header_length = %d\n", \
                     __LINE__, fd, header_length);
            dumpBuffer(NULL, http_header_buf, ret < 1025 ? ret: 1024);
        }
#endif
        return (-PROXY_WAIT_MSG);
    }

}

/*
 * Read all the headers from the stream
 */
static int get_all_headers (int fd, hashmap_t hashofheaders)
{
    char *line = NULL;
    char *header = NULL;
    char *tmp;
    ssize_t linelen;
    ssize_t len = 0;
    unsigned int double_cgi = FALSE;        /* boolean */

    HTTP_PROXY_ASSERT((fd >= 0) && (hashofheaders != NULL), \
                      "get_all_headers: fd/hashofheaders == NULL\n", -1);
    while(1)
    {
#ifdef RELAY_MEM_CTRL
        if ((linelen = readline2 (fd, &line, 0)) <= 0)
#else
        if ((linelen = readline (fd, &line)) <= 0)
#endif
        {
            safefree (header);
#ifndef RELAY_MEM_CTRL
            safefree (line);
#endif
            return -1;
        }

        /*
         * If we received a CR LF or a non-continuation line, then add
         * the accumulated header field, if any, to the hashmap, and
         * reset it.
         */
        if (CHECK_CRLF (line, linelen) || !CHECK_LWS (line, linelen))
        {
            if (!double_cgi
                && len > 0
                && add_header_to_connection (hashofheaders, header,
                                             len) < 0)
            {
                safefree (header);
#ifndef RELAY_MEM_CTRL
                safefree (line);
#endif
                return -1;
            }
            len = 0;
        }

        /*
         * If we received just a CR LF on a line, the headers are
         * finished.
         */
        if (CHECK_CRLF (line, linelen))
        {
            safefree (header);
#ifndef RELAY_MEM_CTRL
            safefree (line);
#endif
            return 0;
        }

        /*
         * BUG FIX: The following code detects a "Double CGI"
         * situation so that we can handle the nonconforming system.
         * This problem was found when accessing cgi.ebay.com, and it
         * turns out to be a wider spread problem as well.
         *
         * If "Double CGI" is in effect, duplicate headers are
         * ignored.
         *
         * FIXME: Might need to change this to a more robust check.
         */
        if (linelen >= 5 && proxy_strncasecmp (line, "HTTP/", 5) == 0)
        {
            double_cgi = TRUE;
        }

        /*
         * Append the new line to the current header field.  that is for the line have continuation-line
         */
        tmp = (char *) saferealloc (header, len + linelen);
        if (tmp == NULL)
        {
            safefree (header);
#ifndef RELAY_MEM_CTRL
            safefree (line);
#endif
            return -1;
        }

        header = tmp;
        memcpy (header + len, line, linelen);
        len += linelen;
#ifndef RELAY_MEM_CTRL
        safefree (line);
#endif
    }
}

/*
 * Extract the headers to remove.  These headers were listed in the Connection
 * and Proxy-Connection headers.
 */
static int remove_connection_headers (hashmap_t hashofheaders)
{
    /*
    ** The Connection general-header field allows the sender to specify options that are desired for that particular connection
    ** and MUST NOT be communicated by proxies over further connections.
    ** The Connection header has the following grammar:
           Connection = "Connection" ":" 1#(connection-token)
           connection-token  = token
    */
    static const char *headers[] =
    {
        "connection",
        "proxy-connection"
    };

    char *data;
    char *ptr;
    ssize_t len;
    int i;

    for (i = 0; i != (sizeof (headers) / sizeof (char *)); ++i)
    {
        /* Look for the connection header.  If it's not found, return. */
        len =
            hashmap_entry_by_key (hashofheaders, headers[i],
                                  (void **) &data);
        if (len <= 0)
            return 0;

        /*
         * Go through the data line and replace any special characters
         * with a NULL.
         */
        ptr = data;
        while ((ptr = strpbrk (ptr, "()<>@,;:\\\"/[]?={} \t"))) // like: ( ) < > @ , ; : \ " / [ ] ? = { }  \t
            *ptr++ = '\0';

        /*
         * All the tokens are separated by NULLs.  Now go through the
         * token and remove them from the hashofheaders.
         */
        ptr = data;
        while (ptr < data + len)
        {
            hashmap_remove (hashofheaders, ptr);

            /* Advance ptr to the next token */
            ptr += strlen (ptr) + 1;
            while (ptr < data + len && *ptr == '\0')
                ptr++;
        }

        /* Now remove the connection header it self. */
        hashmap_remove (hashofheaders, headers[i]);
    }

    return 0;
}

/*
 * If there is a Content-Length header, then return the value; otherwise, return
 * a negative number.
 */
static long get_content_length (hashmap_t hashofheaders)
{
    ssize_t len;
    char *data;
    long content_length = -1;

    len =
        hashmap_entry_by_key (hashofheaders, "content-length",
                              (void **) &data);
    if (len > 0)
        content_length = atol (data);

    return content_length;
}

static char* get_Host(hashmap_t hashofheaders)
{
    char *data;
    ssize_t len;

    len = hashmap_entry_by_key (hashofheaders, "host",
                                (void **) &data);
    if(len > 0)
        return data;
    else
        return NULL;
}

/*
 * Search for Via header in a hash of headers and either write a new Via
 * header, or append our information to the end of an existing Via header.
 *
 * FIXME: Need to add code to "hide" our internal information for security
 * purposes.
 */
static int
write_via_header (int fd, hashmap_t hashofheaders,
                  unsigned int major, unsigned int minor)
{
    ssize_t len;
    char hostname[512];
    char *data;
    int ret;

    if (config.disable_viaheader)
    {
        ret = 0;
        goto done;
    }

    if (config.via_proxy_name)
    {
        strlcpy (hostname, config.via_proxy_name, sizeof (hostname));
    }
    else if (gethostname (hostname, sizeof (hostname)) < 0)
    {
        strlcpy (hostname, "unknown", 512);
    }

    /*
     * See if there is a "Via" header.  If so, again we need to do a bit
     * of processing.
     */
    len = hashmap_entry_by_key (hashofheaders, "via", (void **) &data);
    if (len > 0)
    {
        len_tmp += xsprintf(string_http_header+len_tmp, "Via: %s, %hu.%hu %s (%s/%s)\r\n", \
                            data, major, minor, hostname, PACKAGE,VERSION);
        hashmap_remove (hashofheaders, "via");
    }
    else
    {
        len_tmp += xsprintf(string_http_header+len_tmp, "Via: %hu.%hu %s (%s/%s)\r\n", \
                            major, minor, hostname, PACKAGE, VERSION);
    }

done:
    return ret;
}

/*
 * Number of buckets to use internally in the hashmap.
 */
#define HEADER_BUCKETS 32

/*
 * Here we loop through all the headers the client is sending. If we
 * are running in anonymous mode, we will _only_ send the headers listed
 * (plus a few which are required for various methods).
 *  - rjkaes
 */
static int
process_client_headers (struct conn_s *connptr, hashmap_t hashofheaders)
{
    static const char *skipheaders[] =
    {
        "host",
        "keep-alive",
        "proxy-connection",
        "te",
        "trailers",
        "upgrade"
    };
    int i;
    hashmap_iter iter;
    int ret = 0;

    char *data, *header;
    len_tmp = 0;
    /*
     * Don't send headers if there's already an error, if the request was
     * a stats request, or if this was a CONNECT method (unless upstream
     * proxy is in use.)
     */
    if (connptr->server_fd == -1 || connptr->show_stats
        || (connptr->connect_method && (connptr->upstream_proxy == NULL)))
    {
        log_message (LOG_INFO,
                     "Not sending client headers to remote machine");
        log_message (LOG_INFO, \
                     "\033[0;32mprocess_client_headers: %d %d %d %x\033[0m\n", \
                     connptr->server_fd, connptr->show_stats, connptr->connect_method, \
                     connptr->upstream_proxy);
        return 0;
    }
    log_message(LOG_INFO, "%s:%d cfd = %d, sfd = %d\n", \
                __FUNCTION__, __LINE__, connptr->client_fd, connptr->server_fd);
    /*
     * See if there is a "Content-Length" header.  If so, again we need
     * to do a bit of processing.
     */
    connptr->content_length.client = get_content_length (hashofheaders);

    /*
     * See if there is a "Connection" header.  If so, we need to do a bit
     * of processing. :)
     */
    remove_connection_headers (hashofheaders);

    /*
     * Delete the headers listed in the skipheaders list
     */
    for (i = 0; i != (sizeof (skipheaders) / sizeof (char *)); i++)
    {
        hashmap_remove (hashofheaders, skipheaders[i]);
    }

    /* Send, or add the Via header */
    write_via_header (connptr->server_fd, hashofheaders,
                      connptr->protocol.major,
                      connptr->protocol.minor);

    /*
     * Output all the remaining headers to the remote machine.
     */
    iter = hashmap_first (hashofheaders);
    log_message(LOG_INFO, "%s:%d cfd = %d, sfd = %d\n", \
                __FUNCTION__, __LINE__, connptr->client_fd, connptr->server_fd);
    if (iter >= 0)
    {
        for (; !hashmap_is_end (hashofheaders, iter); ++iter)
        {
            hashmap_return_entry (hashofheaders,
                                  iter, &data, (void **) &header);
            len_tmp += xsprintf(string_http_header+len_tmp, "%s: %s\r\n", data, header);
        }
    }
#if defined(XTINYPROXY_ENABLE)
    if (config.add_xtinyproxy)
    {
        len_tmp += xsprintf(string_http_header+len_tmp, \
                            "X-Tinyproxy: %s\r\n", connptr->client_ip_addr);

    }
#endif
    len_tmp += xsprintf(string_http_header+len_tmp, "\r\n");
    if(len_tmp < 2048)
        log_message(LOG_DEBUG, \
                    "fds %d:%d: header: %s\n", \
                    connptr->client_fd, connptr->server_fd, string_http_header);
#ifdef PROXY_DEBUG_SOCKET_TIMEOUT
    ret = safe_write (__FUNCTION__, __LINE__, connptr->server_fd,
                      string_http_header, strlen(string_http_header));
#else
    ret = safe_write (connptr->server_fd, string_http_header, len_tmp);
#endif
    log_message(LOG_INFO, "ret = %d\n", ret);
    if(ret < 0) return -1;

    /*
     * Spin here pulling the data from the client.
     */
PULL_CLIENT_DATA:
    if (connptr->content_length.client > 0)
    {
        ret = pull_client_data (connptr,
                                connptr->content_length.client);
    }
    log_message(LOG_INFO, "%s %d ret = %d\n", __FUNCTION__, __LINE__, ret);

    return ret;
}

/*
 * Loop through all the headers (including the response code) from the
 * server.
 */

static int process_server_headers (struct conn_s *connptr)
{

    static const char *skipheaders[] =
    {
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
    };

    unsigned char *response_line = Request_Respond_header;

    hashmap_t hashofheaders;
    hashmap_iter iter;
    char *data, *header;
    ssize_t len;
    int i, ret, recvDataLen = 0, headerLen = 0;
    len_tmp = 0;

#ifdef REVERSE_SUPPORT
    struct reversepath *reverse = config.reversepath_list;
#endif
#ifdef RELAY_MEM_CTRL
    ret = check_http_headers_ok(connptr->server_fd, 0, &recvDataLen);
    if(ret <= 0)
    {
        log_message(LOG_DEBUG, \
                    "fds %d-%d: ret = %d\n", \
                    connptr->client_fd, connptr->server_fd, ret);
        return ret;
    }
    headerLen = ret;
    recvDataLen -= ret; // data not header left
    //xprintfk("%d: %d %d\n", __LINE__, headerLen, recvDataLen);
#endif
    /* Get the response line from the remote server. */
retry:
#ifdef RELAY_MEM_CTRL
    len = readline2 (connptr->server_fd, &response_line, 1);
#else
    len = readline (connptr->server_fd, &response_line);
#endif
    if (len <= 0)
    {
        xprintfk("ERROR[%s:%d]: recv should OK\n", __FUNCTION__, __LINE__);
        return -1;
    }

    log_message (LOG_INFO, "%s:%d: response_line = %s\n", \
                 __FUNCTION__, __LINE__, response_line);
    /*
     * Strip the new line and character return from the string.
     */
    if (chomp (response_line, len) == len)
    {
        /*
         * If the number of characters removed is the same as the
         * length then it was a blank line. Free the buffer and
         * try again (since we're looking for a request line.)
         */
#ifndef RELAY_MEM_CTRL
        safefree (response_line);
#endif
        goto retry;
    }

    hashofheaders = hashmap_create (HEADER_BUCKETS);
    if (!hashofheaders)
    {
#ifndef RELAY_MEM_CTRL
        safefree (response_line);
#endif
        return -1;
    }

    /*
     * Get all the headers from the remote server in a big hash
     */

    if (get_all_headers (connptr->server_fd, hashofheaders) < 0)
    {
        log_message (LOG_WARNING,
                     "Could not retrieve all the headers from the remote server.");
        hashmap_delete (hashofheaders);
#ifndef RELAY_MEM_CTRL
        safefree (response_line);
#endif

        /*         indicate_http_error (connptr, 503,
                                     "Could not retrieve all the headers",
                                     "detail",
                                     PACKAGE_NAME " "
                                     "was unable to retrieve and process headers from "
                                     "the remote web server.", NULL); */
        return -1;
    }

    /*
     * At this point we've received the response line and all the
     * headers.  However, if this is a simple HTTP/0.9 request we
     * CAN NOT send any of that information back to the client.
     * Instead we'll free all the memory and return.
     */
    if (connptr->protocol.major < 1)
    {
        hashmap_delete (hashofheaders);
#ifndef RELAY_MEM_CTRL
        safefree (response_line);
#endif
        return 0;
    }
    /* Send the saved response line first */
    /*
    #ifdef PROXY_DEBUG_SOCKET_TIMEOUT
        ret = write_message (__FUNCTION__, __LINE__, connptr->client_fd, "%s\r\n", response_line);
    #else
        ret = write_message (connptr->client_fd, "%s\r\n", response_line);
    #endif

        safefree (response_line);
        if (ret < 0)
            goto ERROR_EXIT;
        */

    len_tmp += xsprintf(string_http_header, "%s\r\n", response_line);
#ifndef RELAY_MEM_CTRL
    safefree (response_line);
#endif
    /*
     * If there is a "Content-Length" header, retrieve the information
     * from it for later use.
     */
    connptr->content_length.server = get_content_length (hashofheaders);

    /*
     * See if there is a connection header.  If so, we need to to a bit of
     * processing.
     */
    remove_connection_headers (hashofheaders);

    /*
     * Delete the headers listed in the skipheaders list
     */
    for (i = 0; i != (sizeof (skipheaders) / sizeof (char *)); i++)
    {
        hashmap_remove (hashofheaders, skipheaders[i]);
    }

    /* Send, or add the Via header */
    ret = write_via_header (connptr->client_fd, hashofheaders,
                            connptr->protocol.major,
                            connptr->protocol.minor);
    if (ret < 0)
        goto ERROR_EXIT;
    /*
     * All right, output all the remaining headers to the client.
     */
    iter = hashmap_first (hashofheaders);
    if (iter >= 0)
    {
        for (; !hashmap_is_end (hashofheaders, iter); ++iter)
        {
            hashmap_return_entry (hashofheaders,
                                  iter, &data, (void **) &header);
            len_tmp += xsprintf(string_http_header+len_tmp, "%s: %s\r\n", data, header);
        }
    }
   len_tmp += xsprintf(string_http_header+len_tmp, "Connection: Close\r\n");
   len_tmp += xsprintf(string_http_header+len_tmp, "\r\n");
#ifdef PROXY_DEBUG_SOCKET_TIMEOUT
    ret = safe_write(__FUNCTION__, __LINE__, connptr->client_fd, string_http_header, len_tmp);
#else
    ret = safe_write(connptr->client_fd, string_http_header, len_tmp);
#endif
    if (ret < 0)
    {
        goto ERROR_EXIT;
    }
    hashmap_delete (hashofheaders);
    /* Write the final blank line to signify the end of the headers
    if (safe_write (connptr->client_fd, "Connection: Close\r\n", 19) < 0)
        return -1;
    if (safe_write (connptr->client_fd, "\r\n", 2) < 0)
        return -1;
    */
#if 1
    // write left data not header
#ifdef PROXY_DEBUG_SOCKET_TIMEOUT
    if(recvDataLen > 0)
    {
        ret = safe_write(__FUNCTION__, __LINE__, connptr->client_fd, http_header_buf+headerLen, recvDataLen);
        if(ret > 0)
        {
            ret = recv(connptr->server_fd, http_header_buf, recvDataLen, 0);
            if(ret < 0) xprintfk("%d: %d\n", __LINE__, ret);
        }
    }
#endif
#else
    if(recvDataLen < 512)
        dumpBuffer(0, http_header_buf+headerLen, recvDataLen);
#endif
    return 0;

ERROR_EXIT:

    hashmap_delete (hashofheaders);
    return -1;
}

#ifdef RELAY_MEM_CTRL
int handle_relay_connection2(int fd, struct conn_s *connptr)
{
    ssize_t bytes_received;
    int status = 0, wstatus = 0;
    unsigned int offSet = 0, totLen = 0;
    log_message(LOG_INFO, "fd = %d, connptr = %x\n", fd, connptr);
    if(fd <= 0 || !connptr)
        return -1;
    if(connptr->client_fd == fd)
    {

        if(connptr->cbuffer0 == NULL)
        {
        Retry0:
            status = read_buffer2 (connptr->client_fd);
            log_message(LOG_DEBUG, \
                        "fd = %d status = %d\n", fd, status);
            if (status > 0)
            {
                wstatus = write_buffer2 (connptr->server_fd, NULL);
                log_message(LOG_DEBUG, \
                            "fd = %d wstatus = %d\n", fd, wstatus);

                if(status == RW_BUFFER_SIZE && wstatus == RW_BUFFER_SIZE)
                {
                    log_message(LOG_DEBUG, \
                                "fd = %d client: RW_BUFFER_SIZE\n", fd);
                    goto Retry0;
                }
                if(wstatus == -EWOULDBLOCK)
                {
                    log_message(LOG_DEBUG, \
                                "fd = %d wstatus = %d\n", fd, wstatus);
                    connptr->cbuffer0 = (struct RelayBuf*)safemalloc(sizeof(struct RelayBuf));
                    relay_mem_frag++;
                    memcpy(connptr->cbuffer0->buffer, buffer_relay.buffer, status);
                    connptr->cbuffer0->total = status;
                    connptr->cbuffer0->index = 0;
                    return -EWOULDBLOCK;
                }
                if(wstatus < 0)
                {
                    log_message(LOG_DEBUG, \
                                "fd %d: %d\n", fd, wstatus);
                    return -1;
                }
                if(wstatus < status)
                {
                    connptr->cbuffer0 = (struct RelayBuf*)safemalloc(sizeof(struct RelayBuf));
                    relay_mem_frag++;
                    memcpy(connptr->cbuffer0->buffer, buffer_relay.buffer+wstatus, \
                           status - wstatus);
                    connptr->cbuffer0->total = status - wstatus;
                    connptr->cbuffer0->index = 0;
                    // send msg
                    return -EWOULDBLOCK;
                }
                else
                    return status;
            }
            else if(status == 0) return 0;
            else if(status == -EWOULDBLOCK) return -PROXY_WAIT_MSG;
            else
            {
                log_message(LOG_DEBUG, "fd %d: %d\n", fd, status);
                return -1;
            }
        }
        else
        {
            totLen = connptr->cbuffer0->total;
            offSet = connptr->cbuffer0->index;
            log_message(LOG_DEBUG, \
                        "fd %d: totLen = %d offSet = %d\n", fd, totLen, offSet);
            wstatus = write_buffer2 (connptr->server_fd, connptr->cbuffer0);
            log_message(LOG_DEBUG, \
                        "fd = %d, wstatus = %d\n", fd, wstatus);
            if(wstatus >= 0)
            {
                if(wstatus == (totLen - offSet))
                {
                    log_message(LOG_DEBUG, \
                                "\033[0;32m fd %d: CLI wstatus == (totLen - offSet) %d \033[0m\n", \
                                fd, wstatus);
                    safefree(connptr->cbuffer0);
                    connptr->cbuffer0 = NULL;
                    connptr->cfd_send_failed = 0;
                    free_relay_mem_frag++;
                    return wstatus;
                }
                else if(wstatus < (totLen - offSet))
                    // send not enough
                {
                    // send msg
                    connptr->cbuffer0->index += wstatus;
                    return -EWOULDBLOCK;
                }
                else
                    log_message(LOG_DEBUG, \
                                "ERROR: fd: %d\n", fd);
            }
            else if(wstatus == -EWOULDBLOCK) return -EWOULDBLOCK;
            else
            {
                log_message(LOG_DEBUG, \
                            "fd %d: %d\n", fd, wstatus);
                return -1;
            }
        }
    }
    else if(connptr->server_fd == fd)
    {

        if(connptr->sbuffer0 == NULL)
        {
        Retry1:
            status = read_buffer2 (connptr->server_fd);
            log_message(LOG_DEBUG, \
                        "fd = %d status = %d\n", fd, status);
            if (status > 0)
            {
                wstatus = write_buffer2 (connptr->client_fd, NULL);
                log_message(LOG_DEBUG, \
                            "fd %d: wstatus = %d\n", fd, wstatus);

                if(status == RW_BUFFER_SIZE && wstatus == RW_BUFFER_SIZE)
                {
                    log_message(LOG_DEBUG, \
                                "fd %d: Srv: RW_BUFFER_SIZE\n", fd);
                    goto Retry1;
                }

                if(wstatus == -EWOULDBLOCK)
                {
                    log_message(LOG_DEBUG, \
                                "fd %d: wstatus = %d\n", fd, wstatus);
                    connptr->sbuffer0 = (struct RelayBuf*)safemalloc(sizeof(struct RelayBuf));
                    relay_mem_frag++;
                    memcpy(connptr->sbuffer0->buffer, buffer_relay.buffer, status);
                    connptr->sbuffer0->total = status;
                    connptr->sbuffer0->index = 0;
                    return -EWOULDBLOCK;
                }
                if(wstatus < 0)
                {
                    log_message(LOG_DEBUG, \
                                "fd %d: %d\n", fd, wstatus);
                    return -1;
                }
                if(wstatus < status)
                {
                    connptr->sbuffer0 = (struct RelayBuf*)safemalloc(sizeof(struct RelayBuf));
                    relay_mem_frag++;
                    memcpy(connptr->sbuffer0->buffer, buffer_relay.buffer+wstatus, \
                           status - wstatus);
                    connptr->sbuffer0->total = status - wstatus;
                    connptr->sbuffer0->index = 0;
                    // send msg
                    return -EWOULDBLOCK;
                }
                else
                    return status;
            }
            else if(status == 0) return 0;
            else if(status == -EWOULDBLOCK) return -PROXY_WAIT_MSG;
            else
            {
                log_message(LOG_DEBUG, \
                            "fd %d: %d\n", fd, status);
                return -1;
            }
        }
        else
        {
            totLen = connptr->sbuffer0->total;
            offSet = connptr->sbuffer0->index;
            log_message(LOG_DEBUG, \
                        "fd: %d totLen = %d offSet = %d\n", \
                        connptr->client_fd, totLen, offSet);
            wstatus = write_buffer2 (connptr->client_fd, connptr->sbuffer0);
            log_message(LOG_DEBUG, \
                        "fd %d: wstatus = %d\n", \
                        connptr->client_fd, wstatus);
            if(wstatus >= 0)
            {
                if(wstatus == (totLen - offSet))
                {
                    log_message(LOG_DEBUG, \
                                "\033[0;32m SRV wstatus == (totLen - offSet) %d \033[0m\n", wstatus);
                    safefree(connptr->sbuffer0);
                    connptr->sbuffer0 = NULL;
                    connptr->sfd_send_failed = 0;
                    free_relay_mem_frag++;
                    return wstatus;
                }
                else if(wstatus < (totLen - offSet))
                    // send not enough
                {
                    // send msg
                    connptr->sbuffer0->index += wstatus;
                    return -EWOULDBLOCK;
                }
                else
                    xprintfk("ERROR: %s: %d\n", __FUNCTION__, __LINE__);
            }
            else if(wstatus == -EWOULDBLOCK) return -EWOULDBLOCK;
            else
            {
                log_message(LOG_DEBUG,"wstatus = %d\n", wstatus);
                return -1;
            }
        }
    }
    else
    {
        xprintfk("ERROR: %s:%d\n", __FUNCTION__, __LINE__);
        return -1;
    }
}

#else
int handle_relay_connection(int fd, struct conn_s *connptr)
{
    ssize_t bytes_received;
    int status = 0, wstatus = 0;
    log_message(LOG_INFO, "fd = %d, connptr = %x\n", fd, connptr);
    if(fd <= 0 || !connptr)
        return -1;
    if(connptr->client_fd == fd)
    {
        status = read_buffer (connptr->client_fd, connptr->cbuffer);
        log_message(LOG_INFO, "%s: status = %d\n", __FUNCTION__,status);
        if (status > 0)
        {
            wstatus = write_buffer (connptr->server_fd, connptr->cbuffer);
            log_message(LOG_INFO, "%s: wstatus = %d\n", __FUNCTION__,status);
            if(wstatus < 0)
            {
                log_message(LOG_WARNING, "%s: wstatus = %d\n", \
                            __FUNCTION__, wstatus);
                xprintfk("C fd = %d status = %d, wstatus = %d\n", fd, status, wstatus);
                return -1;
            }
            xprintfk("C fd = %d status = %d, wstatus = %d\n", fd, status, wstatus);
            return status;
        }
        else
        {
            if(status == 0)
            {
                log_message(LOG_INFO, "%s:%d status = %d\n", \
                            __FUNCTION__, __LINE__, status);
                return -EWOULDBLOCK;
            }
            else
                return -1;
        }

    }
    if(connptr->server_fd == fd)
    {
        status = read_buffer (connptr->server_fd, connptr->sbuffer);
        log_message(LOG_WARNING, "serverfd: %d: read: %d\n", \
                    connptr->server_fd, status);
        log_message(LOG_INFO, "%s: status = %d\n", __FUNCTION__,status);
        if (status > 0)
        {
            wstatus = write_buffer (connptr->client_fd, connptr->sbuffer);
            log_message(LOG_WARNING, "serverfd: %d: write: %d\n", \
                        connptr->server_fd, status);
            log_message(LOG_INFO, "%s: wstatus = %d\n", __FUNCTION__,status);
            if(wstatus < 0)
            {
                log_message(LOG_WARNING, "%s: wstatus = %d\n", \
                            __FUNCTION__, wstatus);
                xprintfk("S fd = %d status = %d, wstatus = %d\n", fd, status, wstatus);
                return -1;
            }
            xprintfk("S fd = %d status = %d, wstatus = %d\n", fd, status, wstatus);
            return status;
        }
        else
        {
            if(status == 0)
            {
                log_message(LOG_INFO, \
                            "status = %d\n", status);
                return -EWOULDBLOCK;
            }
            else
                return -1;
        }
    }
    return 0;
}
#endif

struct conn_s* new_conn_s_struct(int fd)
{
    char peer_ipaddr[IP_LENGTH];
    char peer_string[HOSTNAME_LENGTH];
    int ret_info = 0;
    struct conn_s *connptr = NULL;
    ret_info = getpeer_information (fd, peer_ipaddr, peer_string);
    connptr = initialize_conn (fd, peer_ipaddr, peer_string, NULL);
    if (!connptr)
    {
        s_close (fd);
        return NULL;
    }
    return connptr;
}

int handle_connection_from_server(struct conn_s *connptr)
{
    extern int httpProxyCloseConnection(int fd);
    int ret = 0;
    if(!connptr) return 1;
#ifdef CONFIG_HTTP_PROXY_FTP_SUPPORT
	if(connptr->conn_protocol == PROXY_PROTOCOL_FTP)
	{
		ftpStateStart(connptr);
		return TRUE;
	}
#endif
    if (!(connptr->connect_method && (connptr->upstream_proxy == NULL)))
    {
        ret = process_server_headers (connptr);
        if (ret < 0)
        {
            if(ret == -EAGAIN || ret == -PROXY_WAIT_MSG)
                return ret;
            update_stats (STAT_BADCONN);
            goto fail;
        }
    }
    else
    {
        if (send_ssl_response (connptr) < 0)
        {
            log_message (LOG_ERR,
                         "handle_connection: Could not send SSL greeting "
                         "to client.");

            update_stats (STAT_BADCONN);
            goto fail;
        }
    }
    return TRUE;
fail:
    all_resource_clean(connptr->client_fd, connptr);
    return FALSE;

}

int handle_new_srv_connection(struct conn_s *connptr)
{
    int ret = 0;
#ifdef CONFIG_HTTP_PROXY_FTP_SUPPORT
	if(connptr->conn_protocol == PROXY_PROTOCOL_FTP)
		return 1;
#endif
    if (!connptr->connect_method)
    {
        if(establish_http_connection (connptr, connptr->request) < 0)
        {
            update_stats (STAT_BADCONN);
            goto fail;
        }
    }

    if (process_client_headers (connptr, connptr->hashofheaders) < 0)
    {
        update_stats (STAT_BADCONN);
        goto fail;
    }
    return 1;
fail:
//    httpProxyCloseConnection(connptr->client_fd);
//    destroy_conn (connptr);
    return -1;

}

static int check_for_proxy_packet(struct conn_s *connptr)
{
    char *ret = NULL;
    char *ret2 = NULL;
    if(connptr->request_line)
    {
//      xprintfk("%s: %s\n", __FUNCTION__, connptr->request_line);
        ret = strstr(connptr->request_line, " http://");
        ret2 = strstr(connptr->request_line, "CONNECT ");
//      xprintfk("%s: %s\n", __FUNCTION__, ret);
        if(ret || ret2)
            return 0;
        else
            return -1;
    }
    else
    {
        xprintfk("ERROR: %s:%d: request_line = NULL\n", __FUNCTION__, __LINE__);
        return -1;
    }
}

int handle_connection_from_client(struct conn_s *connptr)
{
    extern int httpProxyRelayNotify(int fd);
    extern int httpProxyCloseConnection(int fd);
    extern int httpProxy_srv_http_conn(int fd);
    ssize_t i;
    char *tttt;
    int ret = 0;
    int sockentBufLen = SOCKET_BUF_SIZE;// MUST > 8k

    log_message(LOG_INFO, "%s, %d\n", __FUNCTION__, __LINE__);

#ifdef RELAY_MEM_CTRL
    ret = check_http_headers_ok(connptr->client_fd, PROXY_CLIENT_FD, NULL);
    if(ret <= 0)
    {
        log_message(LOG_DEBUG, \
                    "fd %d: check_http_headers_ok: %d\n", \
                    connptr->client_fd, ret);
        if(ret == NO_HTTP_PROXY_PACKET)
            goto fail;
        return ret;
    }
#endif
    if ((ret = read_request_line (connptr)) < 0)
    {
        if(ret == -EAGAIN)
        {
            return -EAGAIN;
        }
        else
        {
            update_stats (STAT_BADCONN);
            goto fail;
        }
    }

    // The "hashofheaders" store the client's headers.
    connptr->hashofheaders = hashmap_create (HEADER_BUCKETS);
    if (connptr->hashofheaders == NULL)
    {
        update_stats (STAT_BADCONN);
        goto fail;
    }
    // Get all the headers from the client in a big hash.
    if (get_all_headers (connptr->client_fd, connptr->hashofheaders) < 0)
    {
        log_message (LOG_WARNING, \
                     "Could not retrieve all the headers from the client");
        update_stats (STAT_BADCONN);
        goto fail;
    }
    /*
     * Add any user-specified headers (AddHeader directive) to the
     * outgoing HTTP request.
     */
    for (i = 0; i < vector_length (config.add_headers); i++)
    {
        http_header_t *header = (http_header_t *)
                                vector_getentry (config.add_headers, i, NULL);
        hashmap_insert (connptr->hashofheaders,
                        header->name,
                        header->value, strlen (header->value) + 1);
    }

    connptr->request = process_request (connptr, connptr->hashofheaders);
    if (!connptr->request)
    {
        if (!connptr->show_stats)
        {
            update_stats (STAT_BADCONN);
        }
        goto fail;
    }
    if(connptr->request->path && strlen(connptr->request->path) < 1024)
        log_message(LOG_DEBUG, "fd %d: %s %d %s\n", \
                    connptr->client_fd, connptr->request->host, \
                    connptr->request->port, connptr->request->path);
    else
        log_message(LOG_DEBUG, "fd %d: %s %d\n", \
                    connptr->client_fd, connptr->request->host, \
                    connptr->request->port);

    int stat_tmp = 0;
    connptr->server_fd = opensock (connptr->request->host, connptr->request->port,
                                   connptr->server_ip_addr, &stat_tmp);
    if(conn_fd_pool[connptr->server_fd].status != 0)
        xprintfk("\033[0;32m fd = %d %x \033[0m\n", \
                 conn_fd_pool[connptr->server_fd].fd, conn_fd_pool[connptr->server_fd].status);
    conn_fd_pool[connptr->client_fd].fd = connptr->server_fd;
    conn_fd_pool[connptr->server_fd].fd = connptr->client_fd;
    conn_fd_pool[connptr->client_fd].conn_ptr = connptr;
    conn_fd_pool[connptr->server_fd].conn_ptr = connptr;
    if (stat_tmp == FALSE || connptr->server_fd < 0)
    {
        goto fail;
    }

    log_message(LOG_INFO, "%s: cfd = %d, sfd = %d\n", \
                __FUNCTION__, connptr->client_fd, connptr->server_fd);
    struct sock_usr *ss = soMySocks(P2_MY_QID());
    struct socket *so = ss->skts[connptr->server_fd];
    log_message(LOG_WARNING, "%s:%d: so_stat= 0x%x(%s)\n", \
                __FUNCTION__, __LINE__, so->so_state, getSoStateString(so->so_state));
#if 0
    if(so->so_state & 0x0002)
    {
        if(handle_new_srv_connection(connptr) < 0)
            goto fail;
        log_message (LOG_CONN,
                     "Established connection to host \"%s\" using "
                     "file descriptor %d.\n", \
                     connptr->request->host, connptr->server_fd);
        conn_fd_pool[connptr->client_fd].status = CLIENT_WAIT_SERVER;
        conn_fd_pool[connptr->server_fd].status = SERVER_PUSH_TO_CLIENT;
    }
    if(so->so_state & 0x0004)
    {
        conn_fd_pool[connptr->client_fd].status = CLIENT_WAIT_SERVER;
        conn_fd_pool[connptr->server_fd].status = SERVER_CONNECTION;
    }
#else
    conn_fd_pool[connptr->client_fd].status = CLIENT_WAIT_SERVER;
    conn_fd_pool[connptr->server_fd].status = SERVER_CONNECTION;
#endif
    return connptr->server_fd;
fail:
    log_message(LOG_ERR, "%s, %d\n", __FUNCTION__, __LINE__);
    all_resource_clean(connptr->client_fd, connptr);

    return 0;
}

static int httpProxyCloseConnection(int fd)
{
    int server_side = conn_fd_pool[fd].fd;
    conn_fd_pool[fd].status = SOCKET_STATUS_INITIAL;
    conn_fd_pool[server_side].status = SOCKET_STATUS_INITIAL;
    conn_fd_pool[fd].conn_ptr = NULL;
    conn_fd_pool[server_side].conn_ptr = NULL;
    conn_fd_pool[fd].fd = 0;
    conn_fd_pool[server_side].fd = 0;
    conn_fd_pool[fd].tick= 0;
    conn_fd_pool[server_side].tick = 0;
    return 0;
}

// NOTE: fdSocket only for client side socket
void all_resource_clean(int fdSocket, struct conn_s *connPtr)
{
    if(connPtr)
        destroy_conn (connPtr);
    if(fdSocket)
        httpProxyCloseConnection(fdSocket);
}

