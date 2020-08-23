#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <net/if.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "logging.h"
 
#define PATH_NET_TUN "/dev/net/tun"

int tap_open(const char *ifname, bool nonblock)
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

	if (nonblock)
		fcntl(fd, F_SETFL, O_NONBLOCK);

	return fd;
err_out:
	close(fd);
	return -1;
}
