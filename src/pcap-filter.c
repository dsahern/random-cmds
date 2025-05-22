#define _GNU_SOURCE

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <malloc.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <net/if_arp.h>
#include <net/if.h>
#include <pcap/pcap.h>

struct pcap_opts {
	int sd;
	int err;
	unsigned int pkt_cnt;

	struct sockaddr_ll ll_addr;
};

static void packet_handler(u_char *udata, const struct pcap_pkthdr *pkthdr,
			   const u_char *packet)
{
	struct pcap_opts *opts = (struct pcap_opts *)udata;
	struct ethhdr *eth = (struct ethhdr *)packet;
	ssize_t n;

	opts->pkt_cnt++;
	if (opts->pkt_cnt < 47)
		return;

	if (pkthdr->len < sizeof(*eth))
		return;

	memcpy(opts->ll_addr.sll_addr, eth->h_dest, ETH_ALEN);
	opts->ll_addr.sll_protocol = eth->h_proto;

#if 0
	n = sendto(opts->sd, packet, pkthdr->len, 0,
		   (struct sockaddr *)&opts->ll_addr,
		   sizeof(opts->ll_addr));
#else
	n = write(opts->sd, packet, pkthdr->len);
#endif

	fprintf(stderr, "packet %u len %u (rc %ld)\n", opts->pkt_cnt, pkthdr->len, n);
	if (n != pkthdr->len)
		opts->send_err = 1;
}

int main(int argc, char *argv[])
{
	const char *pcap_in, *pcap_out, *filter;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_opts opts = { 0 };
	struct bpf_program fp;
	int rc = 1;
	pcap_t *ph;

	if (argc != 4) {
		fprintf(stderr, "usage: pcap-filter pcap-file-in file-out filter\n");
		return 1;
	}

	pcap_in = argv[1];
	pcap_out = argv[2];
	filter = argv[3];

	ph = pcap_open_offline(pcap_in, errbuf);
	if (!ph) {
		fprintf(stderr, "pcap_open_offline failed: %s\n", errbuf);
		return 1;
	}

	if (pcap_compile(ph, &fp, filter, 0, 0) < 0) {
		fprintf(stderr, "pcap_compile() failed to compile filter\n");
		goto out;
	}

	if (pcap_setfilter(ph, &fp) < 0) {
		fprintf(stderr, "pcap_setfilter() failed\n");
		goto out;
	}

	pcap_freecode(&fp);

	while (pcap_loop(ph, -1, packet_handler, (u_char *)&opts)) {
		if (opts.err)
			break;
	}

	rc = opts.err;
out:
	pcap_close(ph);
	return rc;
}
