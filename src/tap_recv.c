/* Receive packet over tap device
 *
 * David Ahern <dsahern@gmail.com>
 */

#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "packet.h"
#include "logging.h"

int tap_open(const char *ifname, bool nonblock);

static bool done;

int main(int argc, char *argv[])
{
	const char *ifname;
	char buf[64*1024];
	ssize_t n;
	int fd;

	if (argc != 2) {
		log_error("usage: tap_recv <tap device>\n");
		return 1;
	}

	ifname = argv[1];
	fd = tap_open(ifname, false);
	if (fd < 0)
		return 1;

	while (!done) {
		n = read(fd, buf, sizeof(buf));
		if (n < 0) {
			log_err_errno("read failed");
			break;
		}
		print_pkt(buf, n);
	}
	close(fd);
	return 0;
}
