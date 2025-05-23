/* Receive packet from one tap device and forward to another allowing
 * test cases to make modifications to the packets or packet order
 * including dropping packets.
 */

#define _GNU_SOURCE
#include <features.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "pkt_util.h"
#include "roce_test.h"
#include "logging.h"

#define PATH_NET_TUN "/dev/net/tun"

static bool done;

static unsigned int max_len = 9214;

static int tap_open(const char *ifname)
{
	struct ifreq ifdata;
	int fd, rc;

	fd = open(PATH_NET_TUN, O_RDWR);
	if (fd < 0) {
		log_err_errno("Failed to open %s", PATH_NET_TUN);
		return -1;
	}

	memset(&ifdata, 0, sizeof(ifdata));
	strcpy(ifdata.ifr_name, ifname);
	ifdata.ifr_flags = IFF_TAP | IFF_NO_PI;

	rc = ioctl(fd, TUNSETIFF, (void *) &ifdata);
	if (rc != 0) {
		log_err_errno("ioctl(TUNSETIFF) failed");
		goto err_out;
	}

	fcntl(fd, F_SETFL, O_NONBLOCK);

	return fd;
err_out:
	close(fd);
	return -1;
}

static int do_fwd(int fd_r, int fd_w, const char *desc)
{
	struct pkt *pkt;
	int rc;

	while (1) {
		unsigned int outlen = 0, i;
		struct pkt *pkt_out[64];

		rc = pkt_read(fd_r, max_len, &pkt);
		if (rc < 0) {
			if (errno == EAGAIN)
				break;
			return -errno;
		}

		pkt_set_fd_out(pkt, fd_w);

		if (verbose)
			pkt_print(pkt, "packet in");

		roce_test(pkt, pkt_out, &outlen);

		for (i = 0; i < outlen; ++i) {
			if (verbose)
				pkt_print(pkt_out[i], "packet out");

			if (pkt_write_and_release(pkt_out[i]))
				return -errno;
		}
	}

	return 0;
}

static void sighdlr(int signo)
{
	done = true;
}

static void usage(void)
{
        log_error("netsim OPTS tap1 tap2:\n\n");
        log_error("options:\n");
        log_error("       -v        verbose mode\n");
        log_error("\n");
}

#define GETOPT_STR "v"

int main(int argc, char *argv[])
{
	int fd_tap1, fd_tap2, max_fd;
	fd_set rfds;
	int rc;

	extern char *optarg;

	while ((rc = getopt(argc, argv, GETOPT_STR)) != -1) {
		switch (rc) {
		case 'v':
			verbose++;
			break;
		default:
			usage();
			return 1;
		}
	}

	if (optind + 2 > argc) {
		usage();
		return 1;
	}

	signal(SIGINT, sighdlr);
	signal(SIGTERM, sighdlr);
	signal(SIGHUP, sighdlr);

	fd_tap1 = tap_open(argv[optind]);
	if (fd_tap1 < 0)
		return 1;

	fd_tap2 = tap_open(argv[optind + 1]);
	if (fd_tap2 < 0)
		return 1;

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
