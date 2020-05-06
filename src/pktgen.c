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
 * TCP/UDP
 * tcp and udp headers randomly generated
 *
 * David Ahern <dsahern@gmail.com>
 */

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
#include <arpa/inet.h>
#include <limits.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>
#include <pthread.h>
#include <errno.h>

#define __packed	__attribute__((__packed__))

#define DEFLT_PAUSE_DELAY   100 /* usecs */
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(x[0]))

#define MAX_SRC_MAC  1024   /* make a power of 2 */

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

/*******************************************************************************
 * logging functions
 */

static void log_error(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	return;
}

static void log_msg(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stdout, format, args);
	va_end(args);

	return;
}

static void log_err_errno(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	fprintf(stderr, ": %d: %s\n", errno, strerror(errno));
}

/*******************************************************************************
 * string conversions
 */

static int str_to_int(const char *str, int min, int max, int *value, int base)
{
	int number;
	char *end;

	errno = 0;
	number = (int) strtol(str, &end, base);

	/* entire string should be consumed by conversion 
	 * and value should be between min and max
	 */
	if ( ((*end == '\0') || (*end == '\n')) && (end != str) &&
		(errno != ERANGE) && (min <= number) && (number <= max))
	{
		*value = number;
		return 0;
	}

	return -1;
}

int str_to_ip(const char *str, uint32_t *ip)
{
	struct in_addr addr;

	/* assume dotted decimal given */
	if (inet_aton(str, &addr) == 0)
		return -1;

	*ip = (uint32_t) addr.s_addr;

	return 0;
}

/* mac needs to have length ETH_ALEN */
int str_to_mac(const char *str, unsigned char *mac)
{
	int rc = -1, m, i;
	char *s = strdup(str), *p, *d, tmp[3];

	if (!s)
		return -1;

	p = s;
	tmp[2] = '\0';
	for (i = 0; i < ETH_ALEN; ++i) {
		if (*p == '\0')
			goto out;

		d = strchr(p, ':');
		if (d) {
			*d = '\0';
			if (strlen(p) > 2)
				goto out;

			strcpy(tmp, p);
			p = d + 1;
		} else {
			strncpy(tmp, p, 2);
			p += 2;
		}

		if (str_to_int(tmp, 0, 0xFF, &m, 16) != 0)
			goto out;

		mac[i] = m;
	}

	if (*p == '\0')
		rc = 0;
out:
	free(s);

	return rc;
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

static void print_mac(unsigned char *mac, const char *desc)
{
	if (debug) {
		printf("%s: %x:%x:%x:%x:%x:%x\n",
		       desc, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	}
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

	print_mac(mac, "random_mac");
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

static int arp_create(void *buf, int len, int msglen)
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

struct {
	__u8		synflood;
	__u8		protocol;
	__u8		malformed;
	__u8		fragments;
	__u8		mcast;
	__be32		sip;
	__be32		dip;
} ipv4_opts;

static void ipv4_usage(void)
{
	printf("IPv4 protocol arguments\n"
	"  -s addr       Source address\n"
	"  -d addr       Destination address\n"
	"  -t            TCP transport protocol\n"
	"  -S            TCP syn packets only\n"
	"  -u            UDP transport protocol\n"
	"  -M            Generate multicast destination addresses\n"
	"  -f            IPv4 fragments\n"
	"  -m            Create malformed IPv4 packets\n"
	"\n"
	);
}

static int ipv4_parse(int argc, char *argv[])
{
	int rc;

	extern char *optarg;

	while ((rc = getopt(argc, argv, "hms:d:tufMS")) != -1) {
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
	return 0;
}

static unsigned short ipv4_csum(const void *buf, short nwords)
{
	const unsigned short *p = buf;
	unsigned long csum = 0;
	int n = nwords * 2;

	for (; n > 0; n--)
		csum += *p++;

	csum = (csum >> 16) + (csum & 0xFFFF);
	csum = ~((csum >> 16) + csum) & 0xFFFF;

	return csum;
}

static unsigned short tcpudp_csum(__be32 sip, __be32 dip, unsigned char proto,
				  const unsigned char *buf, unsigned int len)
{
	unsigned char tcpbuf[256];   /* pseudo-header + tcp header */
	__u16 *plen;

	memset(tcpbuf, 0, sizeof(tcpbuf));
	memcpy(tcpbuf, &sip, 4);
	memcpy(tcpbuf + 4, &dip, 4);
	tcpbuf[9] = proto;
	plen = (__u16 *)&tcpbuf[10];
	*plen = htons(len);

	memcpy(tcpbuf+12, buf, len);

	return ipv4_csum(tcpbuf, (len >> 2) + 3);
}

static void fill_udp_hdr(struct iphdr *iph, unsigned int len)
{
	struct udphdr *udph = (struct udphdr *)(iph + 1);

	udph->source = htons(random() & 0xFFFF ? : 6666);
	udph->dest   = htons(random() & 0xFFFF ? : 9999);
	udph->len    = htons(len);
	udph->check  = 0;
	udph->check = tcpudp_csum(iph->saddr, iph->daddr, IPPROTO_UDP,
				  (const unsigned char *)udph, sizeof(*udph));
}

static void fill_tcp_hdr(struct iphdr *iph, unsigned int len)
{
	struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

	tcph->source  = htons(random() & 0xFFFF ? : 6666);
	tcph->dest    = htons(random() & 0xFFFF ? : 9999);
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

	if (ipv4_opts.synflood) {
		tcph->syn = 1;
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
				   (const unsigned char *)tcph, sizeof(*tcph));
}

static int ipv4_create(void *buf, int len, int msglen)
{
	struct iphdr *iph = buf;
	unsigned int hlen = sizeof(*iph);
	unsigned int tot_len = hlen + msglen;

	iph->version = 4;
	iph->ihl     = hlen >> 2;
	iph->ttl     = (uint8_t)random() & 63 ? : 1;
	iph->tos     = 0;
	iph->id      = htons(random() & 0xFFFF ? : 1234);

	if (ipv4_opts.fragments)
		iph->frag_off = htons(IP_MF + 0x0010);
	else
		iph->frag_off = htons(IP_DF);

	iph->saddr = ipv4_opts.sip ? : random();
	iph->daddr = ipv4_opts.dip ? : random();
	if (ipv4_opts.mcast) {
		__u32 addr = ntohl(iph->daddr) & 0x000FFFF;

		iph->daddr = htonl(addr | 0xe0000000);
	}
	iph->protocol = ipv4_opts.protocol;

	iph->tot_len = htons(tot_len);

	if (iph->protocol == IPPROTO_TCP)
		fill_tcp_hdr(iph, msglen);
	else if (iph->protocol == IPPROTO_UDP)
		fill_udp_hdr(iph, msglen);

	/* compute the checksum */
	iph->check = 0;
	iph->check = ipv4_csum(iph, iph->ihl);

	if (ipv4_opts.malformed)
		iph->check &= (__u16) random();

	return tot_len;
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
	int (*create)(void *buf, int len, int msglen);
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
	"  -l len      length of message to send\n"
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

	int msglen;
	int nmsgs;            /* number of messages to send */
	int pause_count;
	int pause_delay;

	struct protocol *proto;

	__u16 vlan;
	__u16 nthreads;

	int srcmac_set;
	unsigned char srcmac[ETH_ALEN];
	unsigned char *smac_array;

	int dstmac_set;
	unsigned char dstmac[ETH_ALEN];
};

static int parse_main_args(int argc, char *argv[], struct opts *opts)
{
	int rc, tmp;
	extern char *optarg;

	while (1)
	{
		rc = getopt(argc, argv, "hi:n:d:s:v:P:D:l:VN:");
		if (rc < 0) break;
		switch(rc)
		{
		case 'i':
			opts->ifname = optarg;
			break;
		case 'n':
			if (str_to_int(optarg, 0, INT_MAX, &opts->nmsgs, 0) != 0) {
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
			if (str_to_int(optarg, 1, 4095, &tmp, 0) != 0) {
				log_error("invalid vlan id\n");
				return -1;
			}
			opts->vlan = tmp;
			break;
		case 'P':
			if (str_to_int(optarg, 1, INT_MAX, &opts->pause_count, 0) != 0) {
				log_error("invalid number of messages for pause\n");
				return -1;
			}
			break;
		case 'l':
			if (str_to_int(optarg, 1, 9000, &opts->msglen, 0) != 0) {
				log_error("invalid message length\n");
				return -1;
			}
			break;
		case 'D':
			if (str_to_int(optarg, 1, INT_MAX, &opts->pause_delay, 0) != 0) {
				log_error("invalid pause time\n");
				return -1;
			}
			break;
		case 'N':
			if (str_to_int(optarg, 1, 64, &tmp, 0) != 0) {
				log_error("invalid number of threads (1-64)\n");
				return -1;
			}
			opts->nthreads = tmp;
			break;
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
		if (strcmp(all_protocols[i].name, argv[optind]) == 0) {
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

static void gen_packets(struct opts *opts)
{
	unsigned char buf[9000];
	struct ethhdr *ethhdr;
	int hlen = sizeof(*ethhdr);
	struct sockaddr_ll ll_addr;
	struct protocol *proto;
	int sent_count = 0;
	int rc, sd;

	proto = opts->proto;

	sd = link_socket();
	if (sd < 0) {
		log_err_errno("socket failed");
		return;
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

	ll_addr.sll_family   = PF_PACKET;
	ll_addr.sll_protocol = ethhdr->h_proto;
	ll_addr.sll_ifindex  = opts->ifidx;
	ll_addr.sll_hatype   = htons(proto->hatype);
	ll_addr.sll_pkttype  = PACKET_OTHERHOST;
	ll_addr.sll_halen    = ETH_ALEN;
	memcpy(ll_addr.sll_addr, opts->dstmac, ETH_ALEN);

	log_msg("sending message ...");
	while (1) {
		int proto_len;
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

		proto_len = proto->create(buf + hlen, sizeof(buf) - hlen,
					  opts->msglen);
		if (proto_len <= 0) /* < 0 = err, == 0 means done */
			break;

		rc = sendto(sd, buf, hlen + proto_len, 0,
			    (struct sockaddr*) &ll_addr, sizeof(ll_addr));
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

static void *thread_gen_packets(void *arg)
{
	gen_packets(arg);

	return NULL;
}

static void do_threads(struct opts *opts)
{
	pthread_attr_t attr;
	pthread_t *id;
	int i;

	id = calloc(opts->nthreads, sizeof(*id));
	if (!id) {
		log_err_errno("calloc failed");
		return;
	}

	if (pthread_attr_init(&attr) != 0) {
		log_err_errno("pthread_attr_init failed");
		return;
	}

	for (i = 0; i < opts->nthreads; ++i) {
		int rc;

		rc = pthread_create(&id[i], &attr, thread_gen_packets, opts);
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
		.msglen = 64,
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
