/*
 *  Simple packet analyzer
 */
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <pcap-bpf.h>
#include <libgen.h>

static void tcp_seq_check(u_char *udata, const struct pcap_pkthdr *pkthdr,
			  const u_char *packet)
{
	static bool do_init = true;
	static unsigned int pkt_count;
	static __u32 tcp_seq_prev;
	static __u32 tcp_seq_next;

	struct ethhdr *ethh;
	struct tcphdr *tcph;
	struct iphdr *iph;
	__u32 seq, tdata;
	int iphlen;

	pkt_count++;

	if (pkthdr->len < (sizeof(*ethh) + sizeof(*iph)))
		return;

	ethh = (struct ethhdr *) packet;
	if (ntohs(ethh->h_proto) != ETH_P_IP)
		return;

	iph = (struct iphdr *)(packet + sizeof(*ethh));
	if (iph->protocol != IPPROTO_TCP)
		return;

	iphlen = iph->ihl << 2;
	printf("[%5u] len %6u iph: len %6u id %5u ",
	       pkt_count, pkthdr->len, ntohs(iph->tot_len), ntohs(iph->id));

	if (pkthdr->len >= (sizeof(*ethh) + iphlen + sizeof(*tcph))) {
		tcph = (struct tcphdr *)((void *) iph + iphlen);

		tdata = ntohs(iph->tot_len) - iphlen - (tcph->doff << 2);
		if (do_init) {
			tcp_seq_prev = ntohl(tcph->seq);
			tcp_seq_next = tcp_seq_prev;
			do_init = false;
		}

		seq = ntohl(tcph->seq);
		printf("  tcp: payload %6u  seq %6u  expected %6u  ack %6u delta %6u  flags %c%c%c%c%c%c%c%c",
			tdata, seq, tcp_seq_next, ntohl(tcph->ack_seq),
			seq - tcp_seq_prev,
			tcph->fin ? 'F' : '.', tcph->syn ? 'S' : '.',
			tcph->rst ? 'R' : '.', tcph->psh ? 'P' : '.',
			tcph->ack ? 'A' : '.', tcph->urg ? 'U' : '.',
			tcph->ece ? 'E' : '.', tcph->cwr ? 'C' : '.');

		tcp_seq_prev = seq;
		tcp_seq_next = seq + tdata;
	}

	printf("\n");
	return;
}

static void icmp_seq_check(u_char *udata, const struct pcap_pkthdr *pkthdr,
			   const u_char *packet)
{
	static unsigned int pkt_count;
	static __u16 icmp_seq_expected;

	struct ethhdr *ethh;
	struct icmphdr *icmph;
	__u16 seq, seq_data;
	struct iphdr *iph;
	int iphlen;
	__u32 len;

	pkt_count++;

	len = pkthdr->len;
	if (len < (sizeof(*ethh) + sizeof(*iph)))
		return;

	ethh = (struct ethhdr *) packet;
	if (ntohs(ethh->h_proto) != ETH_P_IP)
		return;

	iph = (struct iphdr *)(packet + sizeof(*ethh));
	if (iph->protocol != IPPROTO_ICMP)
		return;

	iphlen = iph->ihl << 2;
	if (len < (sizeof(*ethh) + iphlen + sizeof(*icmph)))
		goto out;

	len -= sizeof(*ethh) + iphlen + sizeof(*icmph);

	icmph = (struct icmphdr *)((void *) iph + iphlen);
	switch(icmph->type) {
	case ICMP_ECHO:
		printf("[%5u] len %6u iph: len %6u id %5u",
		       pkt_count, pkthdr->len, ntohs(iph->tot_len),
		       ntohs(iph->id));

		seq = ntohs(icmph->un.echo.sequence);
		printf(" echo id %5u seq %5u",
			ntohs(icmph->un.echo.id), seq);

		if (len > 4) {
			seq_data = ntohs(*((__u16 *)(icmph + 1)));
			printf(" seq_data %5u", seq_data);

			if (seq != seq_data)
				printf(" seq mismatch");

			if (icmp_seq_expected && icmp_seq_expected != seq_data)
				printf(" drops");

			icmp_seq_expected = seq_data + 1;
		}
		printf("\n");
		break;
	}

out:
	return;
}

static void ip_id_check(u_char *udata, const struct pcap_pkthdr *pkthdr,
			const u_char *packet)
{
	static __u16 ip_id_start, ip_id_next;
	static unsigned int pkt_count;
	static __u32 tcp_seq_start;
	static __u32 tcp_ack_start;
	struct ethhdr *ethh;
	struct tcphdr *tcph;
	struct iphdr *iph;
	char c = ' ';
	int iphlen;
	__u16 id;

	pkt_count++;

	if (pkthdr->len < (sizeof(*ethh) + sizeof(*iph)))
		return;

	ethh = (struct ethhdr *) packet;
	if (ntohs(ethh->h_proto) != ETH_P_IP)
		return;

	iph = (struct iphdr *)(packet + sizeof(*ethh));
	if (iph->protocol != IPPROTO_TCP)
		return;

	id = ntohs(iph->id);
	if (!ip_id_start)
		ip_id_start = id;

	if (ip_id_next && id != ip_id_next)
		c = '*';

	ip_id_next = id + 1;
	if (ip_id_next == 0)
		ip_id_next = 1;

	iphlen = iph->ihl << 2;
	printf("%c[%5u] iph: len %6u  id %5u  frag %4x  ttl %3u  options %d",
		c, pkt_count, ntohs(iph->tot_len), id, ntohs(iph->frag_off),
		iph->ttl, iphlen > sizeof(*iph));

	if (pkthdr->len >= (sizeof(*ethh) + iphlen + sizeof(*tcph))) {
		tcph = (struct tcphdr *)((void *) iph + iphlen);

		if (tcp_seq_start == 0)
			tcp_seq_start = ntohl(tcph->seq);

		if (tcp_ack_start == 0)
			tcp_ack_start = ntohl(tcph->ack_seq);

		printf("  tcp: seq %6u  ack %6u  flags %c%c%c%c%c%c%c%c  window %3u  urg_ptr %u",
			ntohl(tcph->seq) - tcp_seq_start,
			ntohl(tcph->ack_seq) - tcp_ack_start,
			tcph->fin ? 'F' : '.', tcph->syn ? 'S' : '.',
			tcph->rst ? 'R' : '.', tcph->psh ? 'P' : '.',
			tcph->ack ? 'A' : '.', tcph->urg ? 'U' : '.',
			tcph->ece ? 'E' : '.', tcph->cwr ? 'C' : '.',
			ntohs(tcph->window), ntohs(tcph->urg_ptr));

		/* TSO packets have a PSH flag set, so add a spacer
		 * to highlight what might be a TSO packet end
		 */
		if (tcph->psh)
			printf("\n");
	}

	printf("\n");
	return;
}

static void usage(const char *prog)
{
	fprintf(stderr, 
		"\nusage: %s -f file\n\n"
		"   -f  file with packets to examine\n"
		"   -i  check continuity of icmp sequence number\n"
		"   -I  check continuity of ip header id\n"
		"   -t  check continuity of tcp sequence numbers\n"
		"\n", prog);
}

int main(int argc, char *argv[])
{
	void (*packet_handler)(u_char *udata,
			       const struct pcap_pkthdr *pkthdr,
			       const u_char *packet) = NULL;
	char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
	char *pcapfile = NULL;
	pcap_t *ph;                    /* pcap handle */
	int rc;

	while ((rc = getopt(argc, argv, "f:iIt")) != -1) {
		switch(rc) {
		case 'f':
			pcapfile = optarg;
			break;
		case 'i':
			packet_handler = icmp_seq_check;
			break;
		case 'I':
			packet_handler = ip_id_check;
			break;
		case 't':
			packet_handler = tcp_seq_check;
			break;
		default:
			usage(basename(argv[0]));
			return 1;

		}
	}

	if (packet_handler == NULL) {
		fprintf(stderr, "analysis not specified.\n");
		return 1;
	}

	if (pcapfile == NULL) {
		fprintf(stderr, "pcap file not specified.\n");
		return 1;
	}

	ph = pcap_open_offline(pcapfile, errbuf);
	if (ph == NULL) {
		fprintf(stderr,"pcap_open_offline failed: %s\n", errbuf);
		return 1;
	}

	if (pcap_datalink(ph) != DLT_EN10MB) {
		fprintf(stderr, "unsupported data link type\n");
		return 1;
	}

	while (pcap_loop(ph, -1, packet_handler, NULL) != 0)
		;

	pcap_close(ph);

	return 0;
}
