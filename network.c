/*
**  Author: hubert_he@realsil.com.cn
**  3rdParty: tinyProxy: https://banu.com/tinyproxy/
** Http Proxy: asynchronous and non-block socket implementation
**
** The functions found here are used for communicating across a
 * network.  They include both safe reading and writing (which are
 * the basic building blocks) along with two functions for
 * easily reading a line of text from the network, and a function
 * to write an arbitrary amount of data to the network.
 */

#include "heap.h"
#include "network.h"
#include "phase2.h"
#include "stdarg.h"
#include "text.h"
#include "http_proxy_main.h"

#define META_DATA 1460
ssize_t proxy_send(int fd, unsigned char *buffer_sent,int length_sent,int flags)
{
    int i = 0;
    unsigned int left = 0;
    ssize_t bytessent, totalSent = 0 ;

    left = length_sent % META_DATA;
    for(i = length_sent / META_DATA; i > 0; i--)
    {
        bytessent = send(fd, buffer_sent, META_DATA, 0);
        if(bytessent == -EWOULDBLOCK || bytessent == -EINTR)
            break;
        if(bytessent < 0)
        {
            //    xprintfk("ERROR: %d: bytessent = %d\n", __LINE__, bytessent);
            return -1;
        }
        totalSent += META_DATA;
        buffer_sent += META_DATA;
    }
    if(i == 0 && left)
    {
        bytessent = send(fd, buffer_sent, left, 0);
        if(bytessent == -EWOULDBLOCK || bytessent == -EINTR)
        {
            //  xprintfk("write_buffer2 bytessent: %d\n", totalSent);
            if(!totalSent) return bytessent;
            else return totalSent;
        }
        if(bytessent < 0)
        {
#if 1
#ifdef HTTP_PROXY_DEBUG_LEVEL_ENABLE
            if(debug_info_level == 0x02)
            {
                dump_conn_request_info(fd);
                xprintfk("ERROR-line: %d: fd = %d %d left = %d\n", __LINE__, fd, bytessent, left);

                if(left < 1024)
                    dumpBuffer(NULL, buffer_sent, left);
            }
#endif
#else
            dump_conn_request_info(fd);
            xprintfk("ERROR-line: %d: fd = %d %d left = %d\n", __LINE__, fd, bytessent, left);

            if(left < 1024)
                dumpBuffer(NULL, buffer_sent, left);
#endif
            return bytessent;
        }
        totalSent += bytessent;
    }
	if ( i > 0 && left)
		xprintfk("+++++++++++++++++");
    return totalSent;
}

/*
 * Write the buffer to the socket. If an EINTR occurs, pick up and try
 * again. Keep sending until the buffer has been sent.
 */
#ifdef PROXY_DEBUG_SOCKET_TIMEOUT
ssize_t safe_write (char *caller, int line,int fd, const char *buffer, size_t count)
#else
ssize_t safe_write (int fd, const char *buffer, size_t count)
#endif
{
    ssize_t len;
    size_t bytestosend;
#if HTTP_PROXY_SOCKET_BUF_ENLARGE
	unsigned int bufSize = 0, bufSize_uint = sizeof(unsigned int);
#endif
    HTTP_PROXY_ASSERT(fd >= 0, "safe_write: fd < 0\n", 0);
    HTTP_PROXY_ASSERT(buffer != NULL, "safe_write: buffer = NULL!\n", 0);
    HTTP_PROXY_ASSERT(count > 0, "safe_write: count <= 0\n", 0);

    bytestosend = count;
    log_message(LOG_DEBUG, "caller = %s line = %d\n", caller, line);
#if HTTP_PROXY_SOCKET_BUF_ENLARGE
	int tmp_retry, sockentBufLen = SOCKET_BUF_SIZE_BIGGER;
	for(tmp_retry = 2; tmp_retry > 0; tmp_retry--)
	{
		len = proxy_send (fd, buffer, bytestosend, 0);
		if (len >= 0) break;
		else if(len == -EINTR || len == -EAGAIN)
		{	
			getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufSize, (socklen_t *)&bufSize_uint);
			if(bufSize < SOCKET_BUF_SIZE_BIGGER)
			{
				xprintfk("%s: %d %s fd = %d, len = %d\n", __FUNCTION__, __LINE__, caller, fd, len);
				setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char*)&sockentBufLen, sizeof(int));
			}
		}
		else
			break;
	}
#else
    len = proxy_send (fd, buffer, bytestosend, 0);
#endif
    log_message(LOG_INFO, "fd = %d: len: %d \n", fd, len);

    if (len < 0)
    {
        if(len == -ETIMEDOUT)
        {
#if 0
            struct sock_usr *ss = soMySocks(P2_MY_QID());
            if(ss)
            {
                struct socket *so = ss->skts[fd];
                if(so)
#if PROXY_DEBUG_SOCKET_TIMEOUT
                    xprintfk("\033[0;32m %s:%d caller:[%s:%d]so_stat= 0x%x(%s) \033[0m\n", \
                             __FUNCTION__, fd, caller, line, so->so_state, getSoStateString(so->so_state));
#else
                    xprintfk("%s:%d so_stat= 0x%x(%s)\n", \
                             __FUNCTION__, fd, so->so_state, getSoStateString(so->so_state));
#endif
                else
                    xprintfk("++++EXCEPTION:fd = %d %s %d\n", fd, __FUNCTION__, __LINE__);
            }
            else
                xprintfk("++++EXCEPTION:fd = %d %s %d\n", fd, __FUNCTION__, __LINE__);
#endif
            return -ETIMEDOUT;
        }
        if (len == -EINTR || len == -EAGAIN)
        {
//              reschedule();
            xprintfk("\033[0;32m safe_write EAGAIN  \033[0m\n");
        }
        else
            return len;
    }
	if(len < 1024)
        log_message(LOG_INFO, "buffer = %s \n", buffer);
    if ((size_t) len != bytestosend)
        xprintfk("\033[0;32m safe_write len = %d, bytestosend = %d \033[0m\n", \
                 len, bytestosend);
    /*
        buffer += len;
        bytestosend -= len;
    */
    return count;
}

/*
 * Matched pair for safe_write(). If an EINTR occurs, pick up and try
 * again.
 */
ssize_t safe_read (int fd, char *buffer, size_t count)
{
    ssize_t len;

    do
    {
        //  len = read (fd, buffer, count);
        len = recv (fd, buffer, count, 0);
    }
    while (len < 0 );

    return len;
}

/*
 * Send a "message" to the file descriptor provided. This handles the
 * differences between the various implementations of vsnprintf. This code
 * was basically stolen from the snprintf() man page of Debian Linux
 * (although I did fix a memory leak. :)
 */
static char proxyWriteBuf[1024 * 8]; /* start with 8 KB and go from there */
#ifdef PROXY_DEBUG_SOCKET_TIMEOUT
int write_message (char *caller, int line, int fd, const char *fmt, ...)
#else
int write_message (int fd, const char *fmt, ...)
#endif
{
    ssize_t n;
    size_t size = (1024 * 8);
    char *buf = proxyWriteBuf, *tmpbuf;
    va_list ap;
    int ret_write = 0;
    while (1)
    {
        va_start (ap, fmt);
        n = vsnprintf (buf, size, fmt, ap);
        va_end (ap);

        /* If that worked, break out so we can send the buffer */
        if (n > -1 && (size_t) n < size)
            break;

        /* Else, try again with more space */
        if (n > -1)
            /* precisely what is needed (glibc2.1) */
            size = n + 1;
        else
            /* twice the old size (glibc2.0) */
            size *= 2;
        if(buf == proxyWriteBuf)
            tmpbuf = (char *) safemalloc(size);
        else
            tmpbuf = (char *) saferealloc (buf, size);
        if (tmpbuf == NULL)
        {
            if(buf != proxyWriteBuf) safefree (buf);
            return -1;
        }
        else
            buf = tmpbuf;
    }
    if(buf != proxyWriteBuf) mem_frag_cnt++;
#if PROXY_DEBUG_SOCKET_TIMEOUT
    if ((ret_write = safe_write (__FUNCTION__, __LINE__, fd, buf, n)) < 0)
    {
#if 1
        log_message(LOG_ERR, "\033[0;32m caller:[%s:%d] fd = %d ret = %d\033[0m\n", \
                 caller, line, fd, ret_write);
#else
		xprintfk("\033[0;32m caller:[%s:%d] fd = %d ret = %d\033[0m\n", \
                 caller, line, fd, ret_write);
#endif
        if(buf != proxyWriteBuf)
        {
            safefree (buf);
            free_mem_frag_cnt++;
        }
        return -1;
    }
#else
    if (safe_write (fd, buf, n) < 0)
    {
        if(buf != proxyWriteBuf)
        {
            safefree (buf);
            free_mem_frag_cnt++;
        }
        return -1;
    }
#endif
    if(buf != proxyWriteBuf)
    {
        safefree (buf);
        free_mem_frag_cnt++;
    }
    return 0;
}

/*
 * Read in a "line" from the socket. It might take a few loops through
 * the read sequence. The full string is allocate off the heap and stored
 * at the whole_buffer pointer. The caller needs to free the memory when
 * it is no longer in use. The returned line is NULL terminated.
 *
 * Returns the length of the buffer on success (not including the NULL
 * termination), 0 if the socket was closed, and -1 on all other errors.
 */


#ifdef RELAY_MEM_CTRL

unsigned char http_header_line_buf[SEGMENT_LEN];

ssize_t readline2(int fd, char **whole_buffer, int flag)
{
    ssize_t ret = -1, line_length = 0;
    memset(http_header_line_buf, 0, SEGMENT_LEN);
    unsigned char *ptr = NULL;
    //Hubert_he-> NOTE: The MSG_PEEK Option, that is a packet be read but not out
    ret = recv (fd, http_header_line_buf, SEGMENT_LEN, MSG_PEEK);
	//dumpBuffer(0, http_header_line_buf, 256);
    if(ret <= 0)
    {
        log_message(LOG_DEBUG, \
                    "fd %d: recv_ret = %d\n", fd, ret);
        return ret;
    }
    ptr = (char *) memchr (http_header_line_buf, '\n', ret);
    if (ptr)
        line_length = ptr - http_header_line_buf + 1;
    else
    {
        log_message(LOG_DEBUG, \
                    "fd %d: PROXY_WAIT_MSG\n", fd);
        return (-PROXY_WAIT_MSG);
    }
    if(flag)
    {
        ret = recv (fd, *whole_buffer, line_length, MSG_DONTWAIT);
        if(ret == line_length)
        {
            (*whole_buffer)[line_length] = '\0';
            return line_length;
        }
        else
        {
            xprintfk("recv Error, %d : %d\n", __FUNCTION__, __LINE__, ret, line_length);
            return -1;
        }
    }
    else
    {
        ret = recv (fd, http_header_line_buf, line_length, MSG_DONTWAIT);
        if(ret == line_length)
        {
            http_header_line_buf[line_length] = '\0';
            *whole_buffer = http_header_line_buf;
            return line_length;
        }
        else
        {
            xprintfk("recv Error, %d : %d\n", __FUNCTION__, __LINE__, ret, line_length);
            return -1;
        }

    }
}
#else
ssize_t readline (int fd, char **whole_buffer)
{
    ssize_t whole_buffer_len;
    char buffer[SEGMENT_LEN];
    char *ptr;

    ssize_t ret;
    ssize_t diff;

    struct read_lines_s
    {
        char *data;
        size_t len;
        struct read_lines_s *next;
    };
    struct read_lines_s *first_line, *line_ptr;

    first_line =
        (struct read_lines_s *) safecalloc (sizeof (struct read_lines_s),
                                            1);
    if (!first_line)
        return -ENOMEM;

    line_ptr = first_line;

    whole_buffer_len = 0;
    int tmp_index = 10;
    for (tmp_index = 10; tmp_index; tmp_index--)
    {
        ret = recv (fd, buffer, SEGMENT_LEN, MSG_PEEK);  // NOTE: The MSG_PEEK Option, that is a packet be read but not out
        if (ret <= 0)
        {
            if(ret == -EAGAIN)
                ret = -EAGAIN;
            goto CLEANUP;
        }

        ptr = (char *) memchr (buffer, '\n', ret);
        if (ptr)
            diff = ptr - buffer + 1;
        else
            diff = ret;

        whole_buffer_len += diff;

        /*
         * Don't allow the buffer to grow without bound. If we
         * get to more than MAXIMUM_BUFFER_LENGTH close.
         */
        if (whole_buffer_len > MAXIMUM_BUFFER_LENGTH)
        {
            ret = -ERANGE;
            goto CLEANUP;
        }

        line_ptr->data = (char *) safemalloc (diff);
        if (!line_ptr->data)
        {
            ret = -ENOMEM;
            goto CLEANUP;
        }

        recv (fd, line_ptr->data, diff, MSG_DONTWAIT);
        line_ptr->len = diff;

        if (ptr)
        {
            line_ptr->next = NULL;
            break;
        }

        line_ptr->next =
            (struct read_lines_s *)
            safecalloc (sizeof (struct read_lines_s), 1);
        if (!line_ptr->next)
        {
            ret = -ENOMEM;
            goto CLEANUP;
        }
        line_ptr = line_ptr->next;
    }

    *whole_buffer = (char *) safemalloc (whole_buffer_len + 1);
    if (!*whole_buffer)
    {
        ret = -ENOMEM;
        goto CLEANUP;
    }

    *(*whole_buffer + whole_buffer_len) = '\0';

    whole_buffer_len = 0;
    line_ptr = first_line;
    while (line_ptr)
    {
        memcpy (*whole_buffer + whole_buffer_len, line_ptr->data,
                line_ptr->len);
        whole_buffer_len += line_ptr->len;

        line_ptr = line_ptr->next;
    }

    ret = whole_buffer_len;

CLEANUP:
    do
    {
        line_ptr = first_line->next;
        if (first_line->data)
            safefree (first_line->data);
        safefree (first_line);
        first_line = line_ptr;
    }
    while (first_line);

    return ret;
}
#endif
/*
 * Convert the network address into either a dotted-decimal or an IPv6
 * hex string.
 */

char *get_ip_string (struct sockaddr *sa, char *buf, size_t buflen)
{
    HTTP_PROXY_ASSERT((sa != NULL) && (buf != NULL) && (buflen != 0), \
                      "get_ip_string: sa/bug/buflen == 0\n", NULL);
    buf[0] = '\0';          /* start with an empty string */

    switch (sa->sa_family)
    {
        case AF_INET:
        {
            struct sockaddr_in *sa_in = (struct sockaddr_in *) sa;

            inet_ntop (AF_INET, &sa_in->sin_addr, buf, buflen);
            break;
        }
        case AF_INET6:
        {
            struct sockaddr_in6 *sa_in6 =
                (struct sockaddr_in6 *) sa;

            inet_ntop (AF_INET6, &sa_in6->sin6_addr, buf, buflen);
            break;
        }
        default:
            /* no valid family */
            return NULL;
    }

    return buf;
}

/*
 * Convert a numeric character string into an IPv6 network address
 * (in binary form.)  The function works just like inet_pton(), but it
 * will accept both IPv4 and IPv6 numeric addresses.
 *
 * Returns the same as inet_pton().
 */
int full_inet_pton (const char *ip, void *dst)
{
    char buf[24], tmp[24];  /* IPv4->IPv6 = ::FFFF:xxx.xxx.xxx.xxx\0 */
    int n;

    HTTP_PROXY_ASSERT((ip != NULL && strlen (ip) != 0) && (dst != NULL), \
                      "full_inet_pton: NULL", -1);
    /*
     * Check if the string is an IPv4 numeric address.  We use the
     * older inet_aton() call since it handles more IPv4 numeric
     * address formats.
     */
    n = inet_aton (ip, (struct in_addr *) dst);
    if (n == 0)
    {
        /*
         * Simple case: "ip" wasn't an IPv4 numeric address, so
         * try doing the conversion as an IPv6 address.  This
         * will either succeed or fail, but we can't do any
         * more processing anyway.
         */
        return inet_pton (AF_INET6, ip, dst);
    }

    /*
     * "ip" was an IPv4 address, so we need to convert it to
     * an IPv4-mapped IPv6 address and do the conversion
     * again to get the IPv6 network structure.
     *
     * We convert the IPv4 binary address back into the
     * standard dotted-decimal format using inet_ntop()
     * so we can be sure that inet_pton will accept the
     * full string.
     */
    snprintf (buf, sizeof (buf), "::ffff:%s",
              inet_ntop (AF_INET, dst, tmp, sizeof (tmp)));
    return inet_pton (AF_INET6, buf, dst);
}
