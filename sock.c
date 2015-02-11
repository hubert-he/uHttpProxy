/*
**  Author: hubert_he@realsil.com.cn
**  3rdParty: tinyProxy: https://banu.com/tinyproxy/
** Http Proxy: asynchronous and non-block socket implementation
** 
** Sockets are created and destroyed here. When a new connection comes in from
 * a client, we need to copy the socket and the create a second socket to the
 * remote server the client is trying to connect to. Also, the listening
 * socket is created and destroyed here. Sounds more impressive than it
 * actually is.
 */

#include "heap.h"
#include "network.h"
#include "sock.h"
#include "text.h"
#include "http_proxy_main.h"
#include "phase2.h"
#include "netdb.h"

/*
 * Bind the given socket to the supplied address.  The socket is
 * returned if the bind succeeded.  Otherwise, -1 is returned
 * to indicate an error.
 */
static int
bind_socket (int sockfd, const char *addr, int family)
{
    struct addrinfo hints, *res, *ressave;

	HTTP_PROXY_ASSERT((sockfd >= 0) && (addr != NULL && strlen (addr) != 0), \
		"bind_socket: addr/fd == NULL\n", -1);
    memset (&hints, 0, sizeof (struct addrinfo));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;

    /* The local port it not important */
    if (getaddrinfo (addr, NULL, &hints, &res) != 0)
        return -1;

    ressave = res;

    /* Loop through the addresses and try to bind to each */
    do
    {
        if (bind (sockfd, res->ai_addr, res->ai_addrlen) == 0)
            break;  /* success */
    }
    while ((res = res->ai_next) != NULL);

    freeaddrinfo (ressave);
    if (res == NULL)        /* was not able to bind to any address */
        return -1;

    return sockfd;
}

/*
 * Open a connection to a remote host.  It's been re-written to use
 * the getaddrinfo() library function, which allows for a protocol
 * independent implementation (mostly for IPv4 and IPv6 addresses.)
 */
int opensock (const char *host, int port, const char *bind_to, int *stat)
{
    extern int httpProxyRelayNotify(int fd);
	int sockentBufLen = SOCKET_BUF_SIZE;// MUST > 8k
	int nodelay_flag = 1;
    int sockfd, n;
    int ret_stat = 0;
	int ticktick = 3;
    struct addrinfo hints, *res, *ressave;
    char portstr[6];

	HTTP_PROXY_ASSERT((host != NULL) && (port > 0), \
		"opensock: host/port == NULL\n", -1);
    memset (&hints, 0, sizeof (struct addrinfo));
//    hints.ai_family = AF_UNSPEC;
	hints.ai_family = AF_INET; // Only support IPv4
    hints.ai_socktype = SOCK_STREAM;

    snprintf (portstr, sizeof (portstr), "%d", port);

    n = getaddrinfo (host, portstr, &hints, &res);
    if (n != 0)
    {
		xprintfk("\033[0;32mopensock: Could not retrieve info for %s\033[0m\n", host);
        return -1;
    }
	
    ressave = res;
//    do
//    {
    sockfd =
        socket (res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0)
        return 0;       /* ignore this one */
	
	setsockopt(sockfd, SOL_SOCKET, SO_SNDBUF, (char*)&sockentBufLen, sizeof(int));
	sockentBufLen = SOCKET_BUF_SIZE_BIG;
	setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, (char*)&sockentBufLen, sizeof(int));
	setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (void *) &nodelay_flag, sizeof(nodelay_flag));
	//xprintfk("opensock: fd = %d %s\n", sockfd,  host);
	xipMakeAsynSock(sockfd, http_proxy_notify_func(HTTP_PROXY_REMOTE_DATA));
    /* Bind to the specified address */
    if (bind_to)
    {
        if (bind_socket (sockfd, bind_to,
                         res->ai_family) < 0)
        {
            s_close (sockfd);
            return 0;       /* can't bind, so try again */
        }
    }
//	 int   nonblock = 1;
//    s_ioctl(sockfd,SIOCNBIO,&nonblock,sizeof(int)); // make it nonblock
    for(ticktick = 3; ticktick; ticktick--)
    {
        if((ret_stat = connect (sockfd, res->ai_addr, res->ai_addrlen)) == 0)
         {
         	*stat = TRUE;
         	break;
        }
        if(ret_stat == -EINPROGRESS)
        {
			continue;
        }
        else
        {
        	if(ret_stat == -EISCONN)
			{
				*stat = TRUE;
				break;
        	}
			else{
				*stat = FALSE;
            	s_close (sockfd);
            	break;
			}
        }
    }
	if(ret_stat == -EINPROGRESS || ret_stat == -EISCONN) 
	{
		log_message(LOG_WARNING, "ret_stat = %d\n", ret_stat);
		*stat = TRUE;
	}
	log_message(LOG_WARNING, "ret_stat = %d\n", ret_stat);
    freeaddrinfo (ressave);
    return sockfd;
}

/*
 * Set the socket to non blocking -rjkaes
 */
int socket_nonblocking (int sock)
{
    setSocketNonblock(sock);
}

/*
 * Set the socket to blocking -rjkaes
 */
int socket_blocking (int sock)
{
    /*
        int nonblocking = 0;
        s_ioctl( sock, SIOCNBIO, &nonblocking, sizeof(int) );
    */
}

/*
 * Takes a socket descriptor and returns the socket's IP address.  Local IP address
 */
int getsock_ip (int fd, char *ipaddr)
{
    struct sockaddr_storage name;
    socklen_t namelen = sizeof (name);

	HTTP_PROXY_ASSERT(fd >= 0, "getsock_ip: fd < 0\n", -1);
    if (getsockname (fd, (struct sockaddr *) &name, &namelen) != 0)
    {
        log_message (LOG_ERR, "getsock_ip: getsockname() error: ");
        return -1;
    }

    if (get_ip_string ((struct sockaddr *) &name, ipaddr, IP_LENGTH) ==
        NULL)
        return -1;

    return 0;
}

/*
 * Return the peer's socket information.  Remote IP Address
 */
int getpeer_information (int fd, char *ipaddr, char *string_addr)
{
    struct sockaddr_storage sa;
    socklen_t salen = sizeof sa;

	HTTP_PROXY_ASSERT((fd >= 0) && (ipaddr != NULL) && (string_addr != NULL), \
		"getpeer_information: fd/ipaddr/stringaddr == NULL\n", -1);
    /* Set the strings to default values */
    ipaddr[0] = '\0';
    strlcpy (string_addr, "[unknown]", HOSTNAME_LENGTH);

    /* Look up the IP address */
    if (getpeername (fd, (struct sockaddr *) &sa, &salen) != 0)
        return -1;

    if (get_ip_string ((struct sockaddr *) &sa, ipaddr, IP_LENGTH) == NULL)
        return -1;

    /* Get the full host name */
    return getnameinfo ((struct sockaddr *) &sa, salen,
                        string_addr, HOSTNAME_LENGTH, NULL, 0, 0);
}
