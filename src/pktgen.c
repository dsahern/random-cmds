/* Simple packet generator
 *
 * Ethernet:
 * Specify smac and dmac in ethernet header or randomly generate. A large
 * set of random source macs will overflow hardware switches in L2 domains,
 * so if the source mac is not specified, a set of random macs is generated
 * and cycled over as each packet is setn.
 *
 * VLAN:
 * One level of vlan id can be specified
 *
 * ARP
 * Generate arp requests and replies. send IP and mac, target IP adn mac can
 * all be independently set.
 *
 * IPv4
 * Source and destination addresses can be set. Other fields randomly set.
 * Malformed packets have wrong checksum.
 *
 * ICMP
 * Send icmp packets.
 *
 * TCP/UDP
 * tcp and udp headers randomly generated
 *
 * David Ahern <dsahern@gmail.com>
 */

#define _GNU_SOURCE
#define __USE_GNU
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/sockios.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <limits.h>
#include <ctype.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <errno.h>

#include "str_utils.h"
#include "raw_input.h"
#include "logging.h"

int tap_open(const char *ifname, bool nonblock);

#define __packed	__attribute__((__packed__))

#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 30
#include <sys/syscall.h>
#define gettid() syscall(SYS_gettid)
#endif

#define DEFLT_PAUSE_DELAY   100 /* usecs */
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

#define MAX_SRC_MAC  1024   /* make a power of 2 */
#define MAX_BUF_SZ  65*1024

struct vlan_ethhdr {
	unsigned char   h_dest[ETH_ALEN];
	unsigned char   h_source[ETH_ALEN];
	__be16          h_vlan_proto;
	__be16          h_vlan_TCI;
	__be16          h_vlan_encapsulated_proto;
};

//static const char bcast_mac[ETH_ALEN] =
//			{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static int debug;

#define PAYLOAD "I am a fake payload; testing 123"

static void set_payload(void *_buf, int plen)
{
	static bool payload_set;
	char *buf = _buf;
	int i;

	if (payload_set)
		return;

	for (i = 0; i < plen; i += sizeof(PAYLOAD)-1)
		strcpy(buf + i, PAYLOAD);

	payload_set = true;
}

/*******************************************************************************
 * string conversions
 */

int str_to_ip(const char *str, uint32_t *ip)
{
	struct in_addr addr;

	/* assume dotted decimal given */
	if (inet_aton(str, &addr) == 0)
		return -1;

	*ip = (uint32_t) addr.s_addr;

	return 0;
}

/*******************************************************************************
 * other generic, utility functions
 */

/* reference: http://stackoverflow.com/questions/109023/best-algorithm-to-count-the-number-of-set-bits-in-a-32-bit-integer
 */
static int NumberOfSetBits(int i)
{
    i = i - ((i >> 1) & 0x55555555);
    i = (i & 0x33333333) + ((i >> 2) & 0x33333333);
    return (((i + (i >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;
}

static void random_mac(unsigned char *mac)
{
	uint32_t a;
	int i;

	for (i = 0; i < 10; ++i) {
		a = (uint32_t) random();
		if (NumberOfSetBits(a) > 7)
			break;
	}

	mac[0] = 0x00;
	mac[1] = 0x3c;
	memcpy(&mac[2], &a, 4);
}

/*******************************************************************************
 * basic socket functions
 */

static int link_socket(void)
{
	return socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
}


static int get_ifindex(const char *ifname)
{
	int sd = link_socket();
	struct ifreq ifdata;
	int rc;

	if (sd < 0) {
		log_err_errno("Failed to get packet socket\n");
		return -1;
	}

	memset(&ifdata, 0, sizeof(ifdata));
	strcpy(ifdata.ifr_name, ifname);

	rc = ioctl(sd, SIOCGIFINDEX, (char *)&ifdata);
	close(sd);
	if (rc != 0) {
		log_err_errno("ioctl(SIOCGIFINDEX) failed");
		return -1;
	}

	return ifdata.ifr_ifindex;
}

/*******************************************************************************
 * arp implementation
 */

struct arp_resp {
	unsigned char sender_mac[ETH_ALEN];
	uint32_t sender_ipv4;
	unsigned char target_mac[ETH_ALEN];
	uint32_t target_ipv4;
	unsigned char padding[18];
} __packed;

struct {
	int malformed;

	__u8 smac_set;
	__u8 tmac_set;

	unsigned char sender_mac[ETH_ALEN];
	uint32_t sender_ipv4;

	unsigned char target_mac[ETH_ALEN];
	uint32_t target_ipv4;
} arp_opts;

static void arp_usage(void)
{
	printf("ARP protocol arguments\n"
	"  -t mac    target mac address\n"
	"  -T ipv4   target IPv4 address\n"
	"  -s mac    sender mac address\n"
	"  -S ipv4   sender IPv4 address\n"
	"  -m        create malformed ARP packets\n"
	"\n"
	);
}

static int arp_parse(int argc, char *argv[])
{
	int rc;
	extern char *optarg;

	while ((rc = getopt(argc, argv, "hmt:T:s:S:"))  != -1) {
		switch(rc)
		{
		case 't':
			if (str_to_mac(optarg, arp_opts.target_mac) != 0) {
				log_error("invalid target mac address\n");
				return -1;
			}
			arp_opts.tmac_set = 1;
			break;

		case 'T':
			if (str_to_ip(optarg, &arp_opts.target_ipv4) != 0) {
				log_error("invalid target ipv4 address\n");
				return -1;
			}
			break;

		case 's':
			if (str_to_mac(optarg, arp_opts.sender_mac) != 0) {
				log_error("invalid sender mac address\n");
				return -1;
			}
			arp_opts.smac_set = 1;
			break;

		case 'S':
			if (str_to_ip(optarg, &arp_opts.sender_ipv4) != 0) {
				log_error("invalid sender ipv4 address\n");
				return -1;
			}
			break;
		case 'm':
			arp_opts.malformed = 1;
			break;
		case 'h':
			arp_usage();
			return 1;

		default:
			return -1;
		}
	}
	return 0;
}

static int arp_create(void *buf, int len)
{
	struct arphdr *hdr = buf;
	struct arp_resp *resp;

	if (len < (sizeof(*hdr)+sizeof(*resp)))
		return -EINVAL;

	hdr->ar_hrd = htons(ARPHRD_ETHER);
	hdr->ar_pro = htons(ETHERTYPE_IP);
	hdr->ar_hln = ETH_ALEN;              /* size of mac address */
	hdr->ar_pln = 4;                     /* size of ipv4 address */

	hdr->ar_op  = arp_opts.tmac_set ? \
				htons(ARPOP_REPLY) : htons(ARPOP_REQUEST);

	buf += sizeof(*hdr);
	resp = (struct arp_resp *) buf;

	/*
 	 * sender mac-ipv4 pair
 	 */
	if (arp_opts.smac_set)
		memcpy(resp->sender_mac, arp_opts.sender_mac, ETH_ALEN);
	else
		random_mac(resp->sender_mac);

	if (arp_opts.sender_ipv4)
		resp->sender_ipv4 = arp_opts.sender_ipv4;
	else
		resp->sender_ipv4 = (uint32_t) random();

	/*
 	 * target mac-ipv4 pair
 	 */
	if (arp_opts.tmac_set)
		memcpy(resp->target_mac, arp_opts.target_mac, ETH_ALEN);
	else
		memset(resp->target_mac, 0, ETH_ALEN);

	if (arp_opts.target_ipv4)
		resp->target_ipv4 = arp_opts.target_ipv4;
	else
		resp->target_ipv4 = (uint32_t) random();

	if (arp_opts.malformed == 1)
		return sizeof(*hdr) + sizeof(*resp) - 8;

	memset(resp->padding, 0, sizeof(resp->padding));

	return sizeof(*hdr) + sizeof(*resp);
}

/*******************************************************************************
 * ipv4
 */

struct ipv4_opts {
	__u8		synflood;
	__u8		protocol;
	__u8		malformed;
	__u8		fragments;
	__u8		mcast;
	__be32		sip;
	__be32		dip;
	__be16		sport;
	__be16		dport;
	int		plen;
} ipv4_opts;

struct {
	__u8		type;
	__u8		code;
	__be16		mtu;
	struct ipv4_opts ipv4_opts;
} icmp_opts;

static void icmp_usage(void)
{
	printf("ICMP arguments\n"
	"  -T type       icmp type\n"
	"  -C code       icmp code\n"
	"  -m mtu        mtu for DEST_UNREACHABLE, FRAG_NEEDED\n"
	"Inner packet:\n"
	"  -s addr       Source address\n"
	"  -d addr       Destination address\n"
	"  -t            TCP transport protocol\n"
	"  -S            TCP syn packets only\n"
	"  -u            UDP transport protocol\n"
	"  -p            destination port\n"
	"  -P            source port\n"
	"\n"
	);
}

static int valid_icmp_type_code(__u8 icmp_type, __u8 icmp_code)
{
	switch(icmp_type) {
	case ICMP_DEST_UNREACH:
		switch(icmp_code) {
		case ICMP_FRAG_NEEDED:
			break;
		default:
			log_error("unknown icmp code\n");
			return -1;
		}
		break;
	default:
		log_error("unknown icmp type\n");
		return -1;
	}

	return 0;
}

static int icmp_code_parse(const char *str)
{
	int val;

	if (isdigit(*str)) {
		if (str_to_int_base(str, 1, 0xff, &val, 10)) {
			log_error("Invalid icmp code\n");
			return -1;
		}
		icmp_opts.code = val;
	} else {
		if (!strcmp(str, "frag")) {
			icmp_opts.code = ICMP_FRAG_NEEDED;
		} else {
			log_error("Unknown icmp code string\n");
			return -1;
		}
	}

	return 0;
}

static int icmp_type_parse(const char *str)
{
	int val;

	if (isdigit(*str)) {
		if (str_to_int_base(str, 1, 0xff, &val, 10)) {
			log_error("Invalid icmp type number\n");
			return -1;
		}
		icmp_opts.type = val;
	} else {
		if (!strcmp(str, "unreach")) {
			icmp_opts.type = ICMP_DEST_UNREACH;
		} else {
			log_error("Unknown icmp type string\n");
			return -1;
		}
	}

	return 0;
}

static int icmp_parse(int argc, char *argv[])
{
	int rc, val;

	extern char *optarg;

	icmp_opts.ipv4_opts.protocol = IPPROTO_ICMP;
	icmp_opts.ipv4_opts.sip = ipv4_opts.dip;
	icmp_opts.ipv4_opts.dip = ipv4_opts.sip;

	while ((rc = getopt(argc, argv, "hT:C:m:s:d:p:P:tuS")) != -1) {
		switch(rc) {
		case 'T':
			if (icmp_type_parse(optarg))
				return -1;
			break;
		case 'C':
			if (icmp_code_parse(optarg))
				return -1;
			break;
		case 'm':
			if (str_to_int_base(optarg, 1, 9999, &val, 10)) {
				log_error("Invalid mtu\n");
				return -1;
			}
			icmp_opts.mtu = htons(val);
			break;
		case 's':
			if (str_to_ip(optarg, &icmp_opts.ipv4_opts.sip) != 0) {
				log_error("Invalid source IP address\n");
				return -1;
			}
			break;
		case 'd':
			if (str_to_ip(optarg, &icmp_opts.ipv4_opts.dip) != 0) {
				log_error("Invalid destination IP address\n");
				return -1;
			}
			break;
		case 'p':
			if (str_to_int_base(optarg, 1, 0xffff, &val, 10)) {
				log_error("Invalid destination port\n");
				return -1;
			}
			icmp_opts.ipv4_opts.dport = htons(val);
			break;
		case 'P':
			if (str_to_int_base(optarg, 1, 0xffff, &val, 10)) {
				log_error("Invalid source port\n");
				return -1;
			}
			icmp_opts.ipv4_opts.sport = htons(val);
			break;
		case 'S':
			icmp_opts.ipv4_opts.protocol = IPPROTO_TCP;
			icmp_opts.ipv4_opts.synflood = 1;
			break;
		case 't':
			icmp_opts.ipv4_opts.protocol = IPPROTO_TCP;
			icmp_opts.ipv4_opts.plen = 16;
			break;
		case 'u':
			icmp_opts.ipv4_opts.protocol = IPPROTO_UDP;
			icmp_opts.ipv4_opts.plen = 16;
			break;
		case 'h':
			icmp_usage();
			return 1;
		default:
			return -1;
		}
	}

	return valid_icmp_type_code(icmp_opts.type, icmp_opts.code);
}

static void ipv4_usage(void)
{
	printf("IPv4 protocol arguments\n"
	"  -s addr       Source address\n"
	"  -d addr       Destination address\n"
	"  -t            TCP transport protocol\n"
	"  -S            TCP syn packets only\n"
	"  -u            UDP transport protocol\n"
	"  -p            destination port\n"
	"  -P            source port\n"
	"  -M            Generate multicast destination addresses\n"
	"  -l len        Length of payload\n"
	"  -f            IPv4 fragments\n"
	"  -m            Create malformed IPv4 packets\n"
	"  icmp          Create icmp packets; remaining arguments parsed for icmp\n"
	"\n"
	);
}

static int ipv4_parse(int argc, char *argv[])
{
	int rc, val;

	extern char *optarg;

	while ((rc = getopt(argc, argv, "hms:d:p:P:tul:fMS")) != -1) {
		switch(rc) {
		case 's':
			if (str_to_ip(optarg, &ipv4_opts.sip) != 0) {
				log_error("Invalid source IP address\n");
				return -1;
			}
			break;
		case 'd':
			if (str_to_ip(optarg, &ipv4_opts.dip) != 0) {
				log_error("Invalid destination IP address\n");
				return -1;
			}
			break;
		case 'p':
			if (str_to_int_base(optarg, 1, 0xffff, &val, 10)) {
				log_error("Invalid destination port\n");
				return -1;
			}
			ipv4_opts.dport = htons(val);
			break;
		case 'P':
			if (str_to_int_base(optarg, 1, 0xffff, &val, 10)) {
				log_error("Invalid source port\n");
				return -1;
			}
			ipv4_opts.sport = htons(val);
			break;
		case 'S':
			ipv4_opts.protocol = IPPROTO_TCP;
			ipv4_opts.synflood = 1;
			break;
		case 't':
			ipv4_opts.protocol = IPPROTO_TCP;
			break;
		case 'u':
			ipv4_opts.protocol = IPPROTO_UDP;
			break;
		case 'M':
			ipv4_opts.mcast = 1;
			break;

		case 'l':
			if (str_to_int(optarg, 1, MAX_BUF_SZ,
				       &ipv4_opts.plen) != 0) {
				log_error("invalid message length\n");
				return -1;
			}
			break;
		case 'f':
			ipv4_opts.fragments = 1;
			break;
		case 'm':
			ipv4_opts.malformed = 1;
			break;
		case 'h':
			ipv4_usage();
			return 1;
		default:
			return -1;
		}
	}

	if (optind < argc) {
		if (!strcmp("icmp", argv[optind])) {
			ipv4_opts.protocol = IPPROTO_ICMP;
			optind++;
			return icmp_parse(argc, argv);
		} else {
			log_error("unknown ipv4 argument\n");
			return -1;
		}
	}
	return 0;
}

static unsigned short ipv4_csum_fold(unsigned long csum)
{
	csum = (csum >> 16) + (csum & 0xFFFF);
	csum = ~((csum >> 16) + csum) & 0xFFFF;

	return csum;
}

static unsigned long __ipv4_csum(const void *buf, int nbytes,
				 unsigned long csum)
{
	const unsigned short *p = buf;
	int n = nbytes >> 1;

	for (; n > 0; n--)
		csum += *p++;

	/* 0 pad odd bytes */
	if (nbytes & 1) {
		const __u8 *pbuf = buf;
		__u8 buf2[2];

		buf2[0] = pbuf[nbytes - 1];
		buf2[1] = 0;
		p = (unsigned short *)buf2;
		csum += *p;
	}

	return csum;
}

static unsigned short ipv4_csum(const void *buf, short nbytes)
{
	return ipv4_csum_fold(__ipv4_csum(buf, nbytes, 0));
}

static unsigned short tcpudp_csum(__be32 sip, __be32 dip, unsigned char proto,
				  const unsigned char *buf, unsigned int len)
{
	unsigned char tcpbuf[12];   /* pseudo-header + tcp header */
	unsigned long csum;
	__u16 *plen;

	memcpy(tcpbuf, &sip, 4);
	memcpy(tcpbuf + 4, &dip, 4);
	tcpbuf[8] = 0;
	tcpbuf[9] = proto;
	plen = (__u16 *)&tcpbuf[10];
	*plen = htons(len);

	csum = __ipv4_csum(tcpbuf, 12, 0UL);
	csum = __ipv4_csum(buf, len, csum);
	return ipv4_csum_fold(csum);
}

static int fill_ipv4_hdr(void *buf, int buflen,
		         const struct ipv4_opts *opts);

static int ipv4_nest;

static unsigned int fill_icmp_hdr(void *buf, int buflen)
{
	struct icmphdr *icmph = (struct icmphdr *)buf;
	unsigned int tot_len = sizeof(*icmph);

	icmph->checksum = 0;
	if (ipv4_nest) {
		icmph->type = ICMP_ECHOREPLY;
		icmph->code = 0;
	} else {
		icmph->type = icmp_opts.type;
		icmph->code = icmp_opts.code;
	}
	ipv4_nest++;

	switch(icmph->type) {
	case ICMP_DEST_UNREACH:
		switch(icmph->code) {
		case ICMP_FRAG_NEEDED:
			memset(&icmph->un.frag, 0, sizeof(icmph->un.frag));
			icmph->un.frag.mtu = icmp_opts.mtu;
			tot_len += fill_ipv4_hdr(buf + tot_len, buflen - tot_len,
						 &icmp_opts.ipv4_opts);
			break;
		}
	}

	icmph->checksum = ipv4_csum(buf, tot_len);

	return tot_len;
}

static int fill_udp_hdr(void *buf, int buflen, struct iphdr *iph,
			const struct ipv4_opts *opts)
{
	struct udphdr *udph = (struct udphdr *)buf;
	int tot_len = opts->plen + sizeof(*udph);

	if (tot_len > buflen)
		return -1;

	if (opts->plen)
		set_payload(buf + sizeof(*udph), opts->plen);

	if (opts->sport)
		udph->source = opts->sport;
	else
		udph->source = htons(random() & 0xFFFF ? : 6666);

	if (opts->dport)
		udph->dest = opts->dport;
	else
		udph->dest = htons(random() & 0xFFFF ? : 9999);

	udph->len    = htons(tot_len);
	udph->check  = 0;
	udph->check = tcpudp_csum(iph->saddr, iph->daddr, IPPROTO_UDP,
				  buf, tot_len);

	return tot_len;
}

static int fill_tcp_hdr(void *buf, int buflen, struct iphdr *iph,
			const struct ipv4_opts *opts)
{
	struct tcphdr *tcph = (struct tcphdr *)buf;
	int tot_len = opts->plen + sizeof(*tcph);

	if (tot_len > buflen)
		return -1;

	if (opts->sport)
		tcph->source = opts->sport;
	else
		tcph->source = htons(random() & 0xFFFF ? : 6666);

	if (opts->dport)
		tcph->dest = opts->dport;
	else
		tcph->dest = htons(random() & 0xFFFF ? : 9999);

	tcph->seq     = htonl(random() & 0xFFFFFFFF ? : 12345);
	tcph->ack_seq = htonl(random() & 0xFFFFFFFF ? : 12346);

	tcph->doff = sizeof(*tcph) >> 2;

	/* start at all 0 */
	tcph->res1 = 0;
#if 0
	tcph->cwr = 0;
	tcph->ece = 0;
#else
	tcph->res2 = 0;
#endif
	tcph->urg = 0;
	tcph->ack = 0;
	tcph->psh = 0;
	tcph->rst = 0;
	tcph->syn = 0;
	tcph->fin = 0;

	if (opts->synflood) {
		tcph->syn = 1;
	} else if (opts->plen) {
		__u16 flags = random() & 0xFFFF;

		if (flags & 0x00ff0000)
			tcph->ack = 1;
		if (flags & 0xff000000)
			tcph->psh = 1;

		set_payload(buf + sizeof(*tcph), opts->plen);
	} else {
		__u16 flags = random() & 0xFFFF;

		tcph->syn = flags & 3 ? 1 : 0;
		if (!tcph->syn && (flags & (3 << 2)))
			tcph->fin = 1;
		if (!tcph->syn && !tcph->fin && (flags & (3 << 4)))
			tcph->rst = 1;
		if (flags & 0x00ff0000)
			tcph->ack = 1;
		if (flags & 0xff000000)
			tcph->psh = 1;
	}

	tcph->window = htons(5840); /* htons(0x7FFF); */
	tcph->urg_ptr = 0;
	tcph->check = 0;
	tcph->check = tcpudp_csum(iph->saddr, iph->daddr, IPPROTO_TCP,
				  buf, tot_len);

	return tot_len;
}

static int fill_ipv4_hdr(void *buf, int buflen,
		         const struct ipv4_opts *opts)
{
	struct iphdr *iph = buf;
	unsigned int hlen = sizeof(*iph);
	int tot_len = hlen;
	int rc = 0;

	if (buflen < hlen) {
		log_error("Invalid message length; can not fit ipv4 header\n");
		return -1;
	}

	iph->version = 4;
	iph->ihl     = hlen >> 2;
	iph->ttl     = (uint8_t)random() & 63 ? : 1;
	iph->tos     = 0;
	iph->id      = htons(random() & 0xFFFF ? : 1234);

	if (opts->fragments)
		iph->frag_off = htons(IP_MF + 0x0010);
	else
		iph->frag_off = htons(IP_DF);

	iph->saddr = opts->sip ? : random();
	iph->daddr = opts->dip ? : random();
	if (opts->mcast) {
		__u32 addr = ntohl(iph->daddr) & 0x000FFFF;

		iph->daddr = htonl(addr | 0xe0000000);
	}

	buf += tot_len;
	buflen -= tot_len;

	iph->protocol = opts->protocol;
	switch (iph->protocol) {
	case IPPROTO_TCP:
		rc = fill_tcp_hdr(buf, buflen, iph, opts);
		break;
	case IPPROTO_UDP:
		rc = fill_udp_hdr(buf, buflen, iph, opts);
		break;
	case IPPROTO_ICMP:
		rc = fill_icmp_hdr(buf, buflen);
		break;
	}

	if (rc < 0)
		return rc;

	tot_len += rc;

	/* compute the checksum */
	iph->tot_len = htons(tot_len);
	iph->check = 0;
	iph->check = ipv4_csum(iph, iph->ihl << 2);

	if (opts->malformed)
		iph->check &= (__u16) random();

	return tot_len;
}

static int ipv4_create(void *buf, int len)
{
	ipv4_nest = 0;
	return fill_ipv4_hdr(buf, len, &ipv4_opts);
}

/*******************************************************************************
 *
 */

struct protocol {
	char *name;
	ushort id;     /* protocol id */
	ushort hatype; /* hardware address type */
	void (*usage) (void);
	int (*parse_args)(int argc, char **argv);
	int (*create)(void *buf, int len);
};

struct protocol all_protocols[] = {
		{.name = "arp",      .id = ETHERTYPE_ARP,     .hatype = ARPHRD_ETHER,
		 .usage = arp_usage, .parse_args = arp_parse, .create = arp_create},

		{.name = "ipv4",      .id = ETHERTYPE_IP,     .hatype = ARPHRD_ETHER,
		 .usage = ipv4_usage, .parse_args = ipv4_parse, .create = ipv4_create},
};

static void main_usage(void)
{
	int i;

	printf("usage: pktgen OPTS protocol PROTO_OPTS\n"
	"\n"
	"  -i ifname   interface to send packets through (required arg)\n"
	"\n"
	"  -s srcmac   source mac in ethernet header (default is random)\n"
	"  -d dstmac   destination mac in ethernet header (default is random)\n"
	"  -v vlan     include vlan header\n"
	"  -n num      number of messages to send (default is 1; 0 = unlimited)\n"
	"  -P num      pause every num packets (default no pause)\n"
	"  -D delay    usec to pause every num packets (default is %d)\n"
	"  -N num      spawn num threads each generating packets based on config (default is 1)\n"
	"\n"
	"  protocol    protocol packet to send.\n\n"
	"Valid protocols:", DEFLT_PAUSE_DELAY);

	for (i = 0; i < ARRAY_SIZE(all_protocols); ++i)
		printf(" %s", all_protocols[i].name);

	printf("\n\n");

	printf("For protocol specific options type pktgen <protocol> -h\n");
}

struct opts {
	const char *ifname;   /* interface to send messages */
	int ifidx;

	int nmsgs;            /* number of messages to send */
	int pause_count;
	int pause_delay;

	int cpu_offset;

	struct protocol *proto;

	__u16 vlan;
	__u16 nthreads;

	int srcmac_set;
	unsigned char srcmac[ETH_ALEN];
	unsigned char *smac_array;

	int dstmac_set;
	unsigned char dstmac[ETH_ALEN];

	/* Do not generate packets, use a static one */
	unsigned char *packet_data;
	int static_packet_len;
};

static int parse_main_args(int argc, char *argv[], struct opts *opts)
{
	int rc, tmp;
	extern char *optarg;

	while (1)
	{
		rc = getopt(argc, argv, "hi:n:d:s:v:P:D:l:VN:R:O:");
		if (rc < 0) break;
		switch(rc)
		{
		case 'i':
			opts->ifname = optarg;
			break;
		case 'n':
			if (str_to_int(optarg, 0, INT_MAX, &opts->nmsgs) != 0) {
				log_error("invalid number of messages to send\n");
				return -1;
			}
			break;
		case 'd':
			if (str_to_mac(optarg, opts->dstmac) != 0) {
				log_error("invalid destination mac\n");
				return -1;
			}
			opts->dstmac_set = 1;
			break;
		case 's':
			if (str_to_mac(optarg, opts->srcmac) != 0) {
				log_error("invalid source mac\n");
				return -1;
			}
			opts->srcmac_set = 1;
			break;
		case 'v':
			if (str_to_int(optarg, 1, 4095, &tmp) != 0) {
				log_error("invalid vlan id\n");
				return -1;
			}
			opts->vlan = tmp;
			break;
		case 'P':
			if (str_to_int(optarg, 1, INT_MAX, &opts->pause_count) != 0) {
				log_error("invalid number of messages for pause\n");
				return -1;
			}
			break;
		case 'D':
			if (str_to_int(optarg, 1, INT_MAX, &opts->pause_delay) != 0) {
				log_error("invalid pause time\n");
				return -1;
			}
			break;
		case 'O':
			if (str_to_int(optarg, 1, INT_MAX, &opts->cpu_offset) != 0) {
				log_error("invalid CPU offset\n");
				return -1;
			}
			break;
		case 'N':
			if (str_to_int(optarg, 1, 64, &tmp) != 0) {
				log_error("invalid number of threads (1-64)\n");
				return -1;
			}
			opts->nthreads = tmp;
			break;
		case 'R': {
			if (parse_raw_input(optarg, &opts->packet_data,
					    &opts->static_packet_len) != 0) {
				log_error("invalid raw input: %s\n");
				return -1;
			}
		}
		case 'V':
			debug++;
			break;
		case 'h':
			main_usage();
			return 1;
		default:
			break;
		}
	}

	return 0;
}

static int parse_args(int argc, char *argv[], struct opts *opts)
{
	int i;

	/* tell getopt to stop parsing once it hits an unknown option
	 * and not to rearrange the argument order
	 */
	setenv("POSIXLY_CORRECT", "yes", 1);

	/* arguments for main program */
	if (parse_main_args(argc, argv, opts) != 0)
		return 1;

	/* next arg should be a protocol */
	if (optind >= argc) {
		printf("optind %d != argc %d\n", optind, argc);
		main_usage();
		return 1;
	}
	fflush(stdout);
	for (i = 0; i < ARRAY_SIZE(all_protocols); ++i) {
		if (!strcmp(all_protocols[i].name, argv[optind])) {
			opts->proto = &all_protocols[i];
			break;
		}
	}
	if (opts->proto == NULL) {
		log_error("protocol not specified\n");
		return 1;
	}
	optind++;

	/* protocol specific arguments */
	if (opts->proto->parse_args && opts->proto->parse_args(argc, argv) != 0) {
		printf("parse_args returned non-0\n");
		return 1;
	}

	/* all the arguments consumed ? */
	if (optind != argc) {
		printf("optind %d != argc %d\n", optind, argc);
		main_usage();

		if (opts->proto->usage)
			opts->proto->usage();
		else
			log_error("protocol %s does not have additional arguments\n",
			       opts->proto->name);
		return 1;
	}

	return 0;
}

static void dump_packet(unsigned char *send_buf, int tot_len)
{
	int i;

	for (i = 0; i < tot_len; i++)
		printf("%02x%c", send_buf[i], i + 1 == tot_len ? '\n' : ' ');
}

static void gen_packets(struct opts *opts)
{
	struct protocol *proto = opts->proto;
	struct sockaddr_ll ll_addr = {
		.sll_family   = PF_PACKET,
		.sll_ifindex  = opts->ifidx,
		.sll_pkttype  = 0,
		.sll_halen    = ETH_ALEN,
		.sll_hatype   = htons(proto->hatype),
	};
	int bufsize = 64*1024*1024;
	unsigned char buf[MAX_BUF_SZ + 64];
	struct ethhdr *ethhdr;
	int hlen = sizeof(*ethhdr);
	bool use_write = false;
	int sent_count = 0;
	int rc, sd;

	if (!strncmp(opts->ifname, "tap", 3)) {
		sd = tap_open(opts->ifname, true);
		if (sd < 0)
			return;
		use_write = true;
	} else {
		sd = link_socket();
		if (sd < 0) {
			log_err_errno("socket failed");
			return;
		}

		if (setsockopt(sd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0)
			perror("setsockopt(SO_SNDBUF)");
	}

	ethhdr = (struct ethhdr *) buf;
	memcpy(ethhdr->h_source, opts->srcmac, ETH_ALEN);
	memcpy(ethhdr->h_dest,   opts->dstmac, ETH_ALEN);
	if (opts->vlan) {
		struct vlan_ethhdr *vehdr = (struct vlan_ethhdr *)buf;

		vehdr->h_vlan_proto = htons(ETHERTYPE_VLAN);
		vehdr->h_vlan_TCI = htons(opts->vlan);
		vehdr->h_vlan_encapsulated_proto = htons(proto->id);

		hlen = sizeof(*vehdr);
	} else {
		ethhdr->h_proto = htons(proto->id);
	}

	memcpy(ll_addr.sll_addr, opts->dstmac, ETH_ALEN);
	ll_addr.sll_protocol = ethhdr->h_proto;

	log_msg("sending message ...");
	while (1) {
		unsigned char *send_buf;
		int tot_len, proto_len;
		int ismac = 1;

		if (opts->srcmac_set == 0) {
			memcpy(ethhdr->h_source,
			       opts->smac_array + ismac * ETH_ALEN,
			       ETH_ALEN);
			print_mac(opts->smac_array + ismac * ETH_ALEN,
				  "source addr");
			ismac++;
			if (ismac >= MAX_SRC_MAC)
				ismac = 0;
		}

		if (opts->dstmac_set == 0)
			random_mac(ethhdr->h_dest);

		if (opts->static_packet_len) {
			send_buf = opts->packet_data;
			tot_len = opts->static_packet_len;
		} else {
			proto_len = proto->create(buf + hlen, sizeof(buf) - hlen);
			if (proto_len <= 0) /* < 0 = err, == 0 means done */
				break;

			send_buf = buf;
			tot_len = hlen + proto_len;
		}

		if (debug >= 3)
			dump_packet(send_buf, tot_len);

		if (use_write) {
			rc = write(sd, send_buf, tot_len);
		} else {
			rc = sendto(sd, send_buf, tot_len, 0,
				    (struct sockaddr*) &ll_addr, sizeof(ll_addr));
		}
		if (rc < 0) {
			log_msg("failed!\n");
			log_err_errno("send failed");
			break;
		}

		sent_count++;
		if (opts->nmsgs && (sent_count >= opts->nmsgs))
			break;

		/* take a breather so as to not overwhelm the netdevice
		 * (overrun stat)
		 */
		if (opts->pause_count && (sent_count % opts->pause_count == 0))
			usleep(opts->pause_delay);
	}

	close(sd);
}

struct thread_arg {
	int cpu;
	struct opts *opts;
};

static void *thread_gen_packets(void *_arg)
{
	struct thread_arg *arg = _arg;
	pid_t tid = gettid();
	cpu_set_t cset;

	CPU_ZERO(&cset);
	CPU_SET(arg->cpu, &cset);
	if (sched_setaffinity(tid, sizeof(cset), &cset) < 0)
		log_err_errno("Failed to set CPU affinity\n");

	gen_packets(arg->opts);

	return NULL;
}

static void do_threads(struct opts *opts)
{
	struct thread_arg *targs;
	pthread_attr_t attr;
	pthread_t *id;
	int i;

	id = calloc(opts->nthreads, sizeof(*id));
	if (!id) {
		log_err_errno("calloc failed");
		return;
	}

	targs = calloc(opts->nthreads, sizeof(*targs));
	if (!targs) {
		log_err_errno("calloc failed");
		return;
	}

	if (pthread_attr_init(&attr) != 0) {
		log_err_errno("pthread_attr_init failed");
		return;
	}

	for (i = 0; i < opts->nthreads; ++i) {
		struct thread_arg *targ = &targs[i];
		int rc;

		targ->opts = opts;
		targ->cpu = opts->cpu_offset + i;
		rc = pthread_create(&id[i], &attr, thread_gen_packets, targ);
		if (rc) {
			log_error("pthread_create failed for thread %d: err %d\n",
				  i, rc);
			break;
		}
	}

	pthread_attr_destroy(&attr);

	for (i = 0; i < opts->nthreads; ++i) {
		void *rc;

		if (id[i] > 0)
			pthread_join(id[i], &rc);
	}

	free(id);
}

int main(int argc, char *argv[])
{
	struct opts opts = {
		.pause_delay = DEFLT_PAUSE_DELAY,
		.nmsgs = 1,
		.nthreads = 1,
	};

	srandom(time(NULL));

	if (parse_args(argc, argv, &opts) != 0)
		return 1;

	if (opts.srcmac_set == 0) {
		int ismac = 0;

		if (debug)
			printf("Generating array of source macs\n");

		opts.smac_array = malloc(MAX_SRC_MAC * ETH_ALEN);
		for (ismac = 0; ismac < MAX_SRC_MAC; ++ismac)
			random_mac(opts.smac_array + ismac * ETH_ALEN);

		/* assign entry 0 */
		memcpy(opts.srcmac, opts.smac_array, ETH_ALEN);
	}

	if (opts.dstmac_set == 0)
		random_mac(opts.dstmac);

	if (opts.ifname == NULL) {
		printf("egress interface not specified\n");
		return 1;
	}

	opts.ifidx = get_ifindex(opts.ifname);
	if (opts.ifidx < 0)
		return 1;

	if (opts.nthreads > 1)
		do_threads(&opts);
	else
		gen_packets(&opts);

	log_msg("done\n");

	free(opts.smac_array);

	return 0;
}
