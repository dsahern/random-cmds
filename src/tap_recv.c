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
	bool forward = false;
	const char *ifname;
	char buf[64*1024];
	ssize_t n;
	int fd;
	int rc;
	extern char *optarg;

	while (1) {
		rc = getopt(argc, argv, "f");
		if (rc < 0) break;

		switch(rc) {
		case 'f':
			forward = true;
			break;
		default:
			log_error("usage: tap_recv [ -f ] <tap device>\n");
			return 1;
		}
	}

	if (optind >= argc) {
		log_error("usage: tap_recv [ -f ] <tap device>\n");
		return 1;
	}

	ifname = argv[optind];
	fd = tap_open(ifname, false);
	if (fd < 0)
		return 1;

	while (!done) {
		n = read(fd, buf, sizeof(buf));
		if (n < 0) {
			log_err_errno("read failed");
			break;
		}
		if (forward) {
			if (write(fd, buf, n) != n)
				log_err_errno("Failed to forward packet");
		} else {
			print_pkt(buf, n);
		}
	}
	close(fd);
	return 0;
}
