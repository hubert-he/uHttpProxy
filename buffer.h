#ifndef _TINYPROXY_BUFFER_H_
#define _TINYPROXY_BUFFER_H_

#include "datatype.h"
//#define READ_BUFFER_SIZE (1024 * 2)
#define RW_BUFFER_SIZE (1460*8)

/* Forward declaration */
struct buffer_s;

struct RelayBuf
{
	unsigned int total;
	unsigned int index;
	unsigned char buffer[RW_BUFFER_SIZE];
};

extern struct RelayBuf buffer_relay;
extern struct buffer_s *new_buffer (void);
extern void delete_buffer (struct buffer_s *buffptr);
extern size_t buffer_size (struct buffer_s *buffptr);

/*
 * Add a new line to the given buffer. The data IS copied into the structure.
 */
extern int add_to_buffer (struct buffer_s *buffptr, unsigned char *data,
                          size_t length);

extern ssize_t read_buffer (int fd, struct buffer_s *buffptr);
extern ssize_t write_buffer (int fd, struct buffer_s *buffptr);

#endif /* __BUFFER_H_ */
