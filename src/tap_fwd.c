/* Receive packet from one tap device and forward to another
 *
 * David Ahern <dsahern@gmail.com>
 */

#define _GNU_SOURCE
#include <features.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <sched.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "logging.h"

#define NS_PREFIX "/run/netns/"

int tap_open(const char *ifname, bool nonblock);

static bool done;

static int switch_ns(const char *ns)
{
	char path[PATH_MAX];
	int fd, ret;

	snprintf(path, sizeof(path), "%s%s", NS_PREFIX, ns);
	fd = open(path, 0);
	if (fd < 0) {
		log_err_errno("Failed to open netns path; can not switch netns");
		return 1;
	}

	ret = setns(fd, CLONE_NEWNET);
	close(fd);

	if (ret < 0)
		log_error("Failed to switch network namespace\n");
	return ret;
}

static int do_fwd(int fd_r, int fd_w, const char *desc)
{
	char buf[64*1024+64];
	ssize_t n;

	while (1) {
		n = read(fd_r, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EAGAIN)
				break;
			log_err_errno("Failed reading fd for %s", desc);
			return -errno;
		}
		if (n && write(fd_w, buf, n) != n) {
			log_err_errno("Failed to forward packet from %s", desc);
			return -errno;
		}
	}
	return 0;
}

int main(int argc, char *argv[])
{
	int fd_tap1, fd_tap2, max_fd;
	fd_set rfds;

	if (argc != 3 && argc != 4) {
		log_error("usage: tap_fwd <tap1> <tap2> <netns>\n");
		return 1;
	}

	fd_tap1 = tap_open(argv[1], false);
	if (fd_tap1 < 0)
		return 1;

	if (argc > 3) {
		if (switch_ns(argv[3]) < 0)
			return 1;
	}

	fd_tap2 = tap_open(argv[2], false);
	if (fd_tap2 < 0)
		return 1;

	fcntl(fd_tap1, F_SETFL, O_NONBLOCK);
	fcntl(fd_tap2, F_SETFL, O_NONBLOCK);

	max_fd = (fd_tap2 > fd_tap1) ? fd_tap2 : fd_tap1;
	max_fd++;

	while (!done) {
		int rc;

		FD_ZERO(&rfds);
		FD_SET(fd_tap1, &rfds);
		FD_SET(fd_tap2, &rfds);

		rc = select(max_fd, &rfds, NULL, NULL, NULL);
		if (rc == 0)
			break;

		if (rc < 0) {
			if (errno == EINTR)
				continue;
			log_err_errno("select failed");
			break;
		}

		if (FD_ISSET(fd_tap1, &rfds)) {
			if (do_fwd(fd_tap1, fd_tap2, "tap1 to 2"))
				break;
		}

		if (FD_ISSET(fd_tap2, &rfds)) {
			if (do_fwd(fd_tap2, fd_tap1, "tap2 to 1"))
				break;
		}
	}

	close(fd_tap1);
	close(fd_tap2);
	return 0;
}
