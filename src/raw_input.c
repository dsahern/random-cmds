// SPDX-License-Identifier: GPL-2.0
/*
 * Read raw packet data from a file
 *
 * Anton Protopopov <aprotopopov@linode.com>
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>

#include "logging.h"

#define MAX_PACKET_SIZE 65536

static inline unsigned char x_to_int(char x)
{
	return (x >= '0' && x <= '9') ? (x - '0') : 10 + (x - 'a');
}

/*
 * parse_raw_input reads packet data from a file. Packet data should be stored
 * in hex separated by spaces or newlines.
 */
int parse_raw_input(const char *path, unsigned char **datap, int *lenp)
{
	static unsigned char data[MAX_PACKET_SIZE];
	char buf[MAX_PACKET_SIZE * 3];
	int data_len = 0;
	int nread;
	char u, l;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		log_err_errno("open: %s", path);
		return -1;
	}

	nread = read(fd, buf, sizeof(buf));
	if (nread < 0) {
		log_err_errno("read: %s", path);
		close(fd);
		return -1;
	}

	close(fd);

	for (int i = 0; i < nread; i++) {
		if (isspace(buf[i]))
			continue;

		if (i + 1 == nread) {
			log_error("truncated input: %s\n", path);
			return -1;
		}

		u = tolower(buf[i]);
		if (!isxdigit(u)) {
			log_error("%s: bad char #%d: %c\n", path, i, buf[i]);
			return -1;
		}

		i++;
		l = tolower(buf[i]);
		if (!isxdigit(l)) {
			log_error("%s: bad char #%d: %c\n", path, i, buf[i]);
			return -1;
		}

		data[data_len++] = (x_to_int(u) << 4) + x_to_int(l);
	}

	*datap = data;
	*lenp = data_len;
	return 0;
}
