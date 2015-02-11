/*
**  Author: hubert_he@realsil.com.cn
**  3rdParty: tinyProxy: https://banu.com/tinyproxy/
** Http Proxy: asynchronous and non-block socket implementation
** 
**
** The buffer used in each connection is a linked list of lines. As the lines
 * are read in and written out the buffer expands and contracts. Basically,
 * by using this method we can increase the buffer size dynamically. However,
 * we have a hard limit of 64 KB for the size of the buffer. The buffer can be
 * thought of as a queue were we act on both the head and tail. The various
 * functions act on each end (the names are taken from what Perl uses to act on
 * the ends of an array. :)
 */

#include "buffer.h"
#include "heap.h"
#include "errno.h"
#include "conns.h"

#define BUFFER_HEAD(x) (x)->head
#define BUFFER_TAIL(x) (x)->tail

struct bufline_s
{
    unsigned char *string;  /* the actual string of data */
    struct bufline_s *next; /* pointer to next in linked list */
    size_t length;          /* length of the string of data */
    size_t pos;             /* start sending from this offset */
};

/*
 * The buffer structure points to the beginning and end of the buffer list
 * (and includes the total size)
 */
struct buffer_s
{
    struct bufline_s *head; /* top of the buffer */
    struct bufline_s *tail; /* bottom of the buffer */
    size_t size;            /* total size of the buffer */
};
/*
 * Reads the bytes from the socket, and adds them to the buffer.
 * Takes a connection and returns the number of bytes read.
 */

struct RelayBuf buffer_relay;
void clearRelayBuf()
{
    buffer_relay.total = 0;
    buffer_relay.index = 0;
}
#define MSG_DONTWAIT 0x80
ssize_t read_buffer2(int fd)
{
    ssize_t bytesin;
	HTTP_PROXY_ASSERT(fd >= 0, "read_buffer2: fd < 0\n", -1);
    clearRelayBuf();
    bytesin = recv (fd, buffer_relay.buffer, RW_BUFFER_SIZE, MSG_DONTWAIT);
//   xprintfk("read_buffer2 bytesin = %d\n", bytesin);
    if (bytesin > 0)
    {
        buffer_relay.total = bytesin;
        buffer_relay.index = 0;
        return bytesin;
    }
    else
    {
        switch (bytesin)
        {
            case 0:
                bytesin = 0;
                break;
            case -EWOULDBLOCK:
            case -EINTR:
                bytesin = -EWOULDBLOCK;
                break;
            default:
                log_message (LOG_DEBUG, \
                             "fd %d: ret = %d recv() error\n", \
                             fd, bytesin);
                bytesin = -1;
                break;
        }
        return bytesin;
    }
}
/*
 * Write the bytes in the buffer to the socket.
 * Takes a connection and returns the number of bytes written.
 */
#define META_DATA (1460)
ssize_t write_buffer2 (int fd, struct RelayBuf *wBuffer)
{
    ssize_t bytessent, totalSent = 0 ;
    unsigned char *buffer_sent = NULL;
    unsigned int length_sent = 0, i = 0, left = 0;
    if(wBuffer == NULL)
    {
        buffer_sent = buffer_relay.buffer;
        length_sent = buffer_relay.total - buffer_relay.index;
    }
    else
    {
        buffer_sent = wBuffer->buffer + wBuffer->index;
        length_sent = wBuffer->total - wBuffer->index;
    }
	log_message(LOG_DEBUG, "buffer_sent = %x  length_sent = %d\n", buffer_sent, length_sent);
    left = length_sent % META_DATA;
    for(i = length_sent / META_DATA; i > 0; i--)
    {
        bytessent = send(fd, buffer_sent, META_DATA, 0);
		log_message(LOG_DEBUG, "bytessent = %d\n", bytessent);
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
		log_message(LOG_DEBUG, "bytessent = %d\n", bytessent);
        if(bytessent == -EWOULDBLOCK || bytessent == -EINTR)
        {
            //  xprintfk("write_buffer2 bytessent: %d\n", totalSent);
            return totalSent;
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
        totalSent += left;
    }
//    xprintfk("write_buffer2 bytessent: %d\n", totalSent);
    return totalSent;
}
