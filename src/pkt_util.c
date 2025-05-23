/*
 * packet parsing functions
 */

#include <sys/time.h>
#include <linux/types.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "pkt_util.h"
#include "motcp_hdr.h"
#include "roce_hdr.h"
#include "logging.h"

#define IP_MF           0x2000          /* Flag: "More Fragments"       */
#define IP_OFFSET       0x1FFF          /* "Fragment Offset" part       */

enum pkt_type {
	PKT_TYPE_UNSET,

	PKT_TYPE_ROCE,
	PKT_TYPE_MOTCP,

	PKT_TYPE_OTHER,
};

struct pkt {
	unsigned char *data;
	unsigned char *payload;
	unsigned int len;
	unsigned int alloc_len;

	enum pkt_type ptype;

	/* pointers to protocol headers within data */

	struct ethhdr *eth;

	/* network */
	struct iphdr *iph;
	struct ipv6hdr *ip6h;

	/* transport */
	struct tcphdr *tcph;
	struct udphdr *udph;

	/* ULP */
	union {
		struct enf_bth  *bth;      /* MoTCP */
		struct roce_bth *roce_bth;
	};

	int fd_in;
	int fd_out;
};

static inline bool ip_is_fragment(const struct iphdr *iph)
{
	return (iph->frag_off & htons(IP_MF | IP_OFFSET)) != 0;
}

/* unaligned ptr handling from Linux */

#define __packed __attribute__((packed))

#define __get_unaligned_t(type, ptr) ({                                             \
        const struct { type x; } __packed * __get_pptr = (typeof(__get_pptr))(ptr); \
        __get_pptr->x;                                                              \
})

static inline __u16 get_unaligned_be16(const void *p)
{
        return ntohs(__get_unaligned_t(__be16, p));
}

static void print_tcp(const struct pkt *pkt, const char *src, const char *dst)
{
	printf("  %s/%d > %s/%d TCP MoTCP %d",
	       src, ntohs(pkt->tcph->source),
	       dst, ntohs(pkt->tcph->dest),
	       !!pkt->bth);
}

static void print_udp(const struct pkt *pkt, const char *src, const char *dst)
{
	struct roce_bth *bth = pkt->roce_bth;

	printf("  %s/%d > %s/%d UDP RoCE %d",
	       src, ntohs(pkt->udph->source),
	       dst, ntohs(pkt->udph->dest), !!bth);

	if (bth) {
		printf("  opcode %d flags %x qpn %u psn %u ack %d",
		       bth->opcode, bth->flags, bth_qpn(bth), bth_psn(bth),
		       bth_ack(bth));
	}
}

static void print_transport(const struct pkt *pkt, const char *src, const char *dst)
{
	if (pkt->tcph)
		print_tcp(pkt, src, dst);
	else if (pkt->udph)
		print_udp(pkt, src, dst);
	else
		printf("  protocol %u: %s > %s",
		       pkt->iph ? pkt->iph->protocol : pkt->ip6h->nexthdr,
		       src, dst);

	printf(" length %u", pkt->len);
}

static void print_ipv6(const struct pkt *pkt)
{
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &pkt->ip6h->saddr, src, sizeof(src));
	inet_ntop(AF_INET6, &pkt->ip6h->daddr, dst, sizeof(dst));

	print_transport(pkt, src, dst);
	printf("\n");
}

static void print_ipv4(const struct pkt *pkt)
{
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &pkt->iph->saddr, src, sizeof(src));
	inet_ntop(AF_INET, &pkt->iph->daddr, dst, sizeof(dst));

	print_transport(pkt, src, dst);
	printf("\n");
}

static void timestamp(void)
{
	char buf[128];
	unsigned int len = sizeof(buf);
	struct timeval tv;
	struct tm ltime;

	gettimeofday(&tv, NULL);

	if (localtime_r(&tv.tv_sec, &ltime) == NULL) {
		buf[0] = '\0';
	} else {
		char date[64];

		strftime(date, sizeof(date), "%H:%M:%S", &ltime);
		snprintf(buf, len, "%s.%06d", date, (int) tv.tv_usec);
	}

	printf("%s", buf);
}

void pkt_print(const struct pkt *pkt)
{
	timestamp();

	if (pkt->iph)
		print_ipv4(pkt);
	else if (pkt->ip6h)
		print_ipv6(pkt);
	else
		printf("Not an IPv4 or IPv6 packet\n");
}

static void parse_exp_option(struct pkt *pkt, int opsize, const __u8 *ptr)
{
	__u16 exid;

	exid = get_unaligned_be16(ptr);
	ptr += 2;

	if (exid == TCPOPT_EXP_ENF_BTH_EXID && opsize >= TCPOLEN_EXP_ENF_BTH) {
		struct enf_bth *bth = (struct enf_bth *)ptr;

		pkt->bth = bth;
	}
}

/* derviced from tcp_parse_options */
static void parse_tcp_opt(struct pkt *pkt, const void *_ptr, int len)
{
	const unsigned char *ptr = _ptr;

	while (len > 0) {
		int opcode = *ptr++;
		int opsize;

		switch (opcode) {
		case TCPOPT_EOL:
			goto out;
		case TCPOPT_NOP:        /* Ref: RFC 793 section 3.1 */
			len--;
			continue;
		default:
			if (len < 2)
				goto out;
			opsize = *ptr++;
			if (opsize < 2) /* "silly options" */
				goto out;
			if (opsize > len)
				goto out; /* don't parse partial options */
			switch (opcode) {
			case TCPOPT_EXP:
				parse_exp_option(pkt, opsize, ptr);
				break;
			}

			ptr += opsize-2;
			len -= opsize;
		}
	}
out:
	return;
}

static int parse_tcp(struct pkt *pkt, unsigned char *buf, unsigned int len)
{
	struct tcphdr *tcph = (struct tcphdr *)buf;
	unsigned int hlen = sizeof(*tcph);

	if (len < hlen)
		return -1;

	pkt->tcph = tcph;
	hlen = tcph->doff << 2;
	if (len < hlen)
		return -1;

	hlen -= sizeof(*tcph);
	if (hlen)
		parse_tcp_opt(pkt, tcph + 1, hlen);

	len -= hlen;

	return len;
}

static int parse_rocev2(struct pkt *pkt, unsigned char *buf, unsigned int len)
{
	struct roce_bth *bth = (struct roce_bth *)buf;
	unsigned int hlen = sizeof(*bth);

	if (len < hlen)
		return -1;

	if (pkt->udph->dest == htons(ROCE_V2_UDP_DPORT)) {
		pkt->ptype = PKT_TYPE_ROCE;
		pkt->roce_bth = bth;
	}

	len -= hlen;

	return len;
}

static int parse_udp(struct pkt *pkt, unsigned char *buf, unsigned int len)
{
	struct udphdr *udph = (struct udphdr *)buf;
	unsigned int hlen = sizeof(*udph);

	if (len < hlen)
		return -1;

	pkt->udph = udph;

	buf += hlen;
	len -= hlen;

	return parse_rocev2(pkt, buf, len);
}

static int parse_transport(struct pkt *pkt, unsigned char *buf,
			   unsigned int len, unsigned char proto)
{
	switch (proto) {
	case IPPROTO_TCP:
		return parse_tcp(pkt, buf, len);
	case IPPROTO_UDP:
		return parse_udp(pkt, buf, len);
	}

	return 0;
}

static int parse_ipv6(struct pkt *pkt, unsigned char *buf, unsigned int len)
{
	struct ipv6hdr *ip6h = (struct ipv6hdr *)buf;
	unsigned int hlen = sizeof(*ip6h);

	if (len < hlen)
		return -1;

	pkt->ip6h = ip6h;

	buf += hlen;
	len -= hlen;

	return parse_transport(pkt, buf, len, ip6h->nexthdr);
}

static int parse_ipv4(struct pkt *pkt, unsigned char *buf, unsigned int len)
{
	struct iphdr *iph = (struct iphdr *)buf;
	unsigned int hlen = sizeof(*iph);

	if (len < hlen)
		return -1;

	pkt->iph = iph;
	hlen = iph->ihl << 2;

	if (ip_is_fragment(iph))
		return 0;

	buf += hlen;
	len -= hlen;

	return parse_transport(pkt, buf, len, iph->protocol);
}

static int pkt_parse(struct pkt *pkt)
{
	unsigned char *buf = pkt->data;
	const struct ethhdr *eth = (const struct ethhdr *)buf;
	unsigned int hlen = sizeof(*eth);
	unsigned int len = pkt->len;
	__be16 h_proto;
	int rc = 0;

	if (len < hlen) {
		log_error("Invalid pkt - no ethernet header\n");
		return -EINVAL;
	}

	h_proto = eth->h_proto;
	if (ntohs(h_proto) == ETH_P_8021Q) {
		log_error("Invalid pkt - do not support vlans\n");
		return -EINVAL;
	}

	buf += hlen;
	len -= hlen;

	pkt->ptype = PKT_TYPE_OTHER;

	switch (ntohs(h_proto)) {
	case ETH_P_IP:
		rc = parse_ipv4(pkt, buf, len);
		break;
	case ETH_P_IPV6:
		rc = parse_ipv6(pkt, buf, len);
		break;
	}

	if (rc > 0) {
		pkt->payload = pkt->data + rc;
		rc = 0;
	}

	return rc;
}

struct pkt *pkt_copy(struct pkt *pkt_in)
{
	struct pkt *pkt;

	pkt = calloc(1, sizeof(*pkt));
	if (pkt) {
		*pkt = *pkt_in;

		pkt->data = calloc(1, pkt_in->alloc_len);
		if (!pkt->data) {
			free(pkt);
			return NULL;
		}

		memcpy(pkt->data, pkt_in->data, pkt_in->len);
	}

	return pkt;
}

struct pkt *pkt_alloc(unsigned int max_len)
{
	struct pkt *pkt;

	pkt = calloc(1, sizeof(*pkt));
	if (pkt) {
		pkt->data = calloc(1, max_len);
		if (!pkt->data) {
			free(pkt);
			return NULL;
		}
		pkt->alloc_len = max_len;
	}

	return pkt;
}

void pkt_free(struct pkt *pkt)
{
	free(pkt->data);
	free(pkt);
}

int pkt_read(int fd, unsigned int max_len, struct pkt **ppkt)
{
	struct pkt *pkt;
	ssize_t n;

	pkt = pkt_alloc(max_len);
	if (!pkt)
		return -ENOMEM;

	n = read(fd, pkt->data, max_len);
	if (n < 0) {
		pkt_free(pkt);
		return -errno;
	}

	if (n == 0)
		return -ENOENT;

	pkt->len = n;
	if (pkt_parse(pkt)) {
		pkt_free(pkt);
		return -errno;
	}

	pkt->fd_in = fd;

	*ppkt = pkt;

	return 0;
}

int pkt_write(struct pkt *pkt)
{
	int rc = 0;

	if (write(pkt->fd_out, pkt->data, pkt->len) != pkt->len)
		rc = -errno;

	return rc;
}

int pkt_write_and_release(struct pkt *pkt)
{
	int rc;

	rc = pkt_write(pkt);
	pkt_free(pkt);

	return rc;
}

struct iphdr *pkt_iph(struct pkt *pkt)
{
	return pkt->iph;
}

struct ipv6hdr *pkt_ip6h(struct pkt *pkt)
{
	return pkt->ip6h;
}

bool pkt_is_roce(struct pkt *pkt)
{
	return !!pkt->roce_bth;
}

bool pkt_is_motcp(struct pkt *pkt)
{
	return !!pkt->bth;
}

struct roce_bth *pkt_roce_bth(struct pkt *pkt)
{
	return pkt->roce_bth;
}

struct enf_bth *pkt_motcp_bth(struct pkt *pkt)
{
	return pkt->bth;
}

unsigned char *pkt_payload(struct pkt *pkt)
{
	return pkt->payload;
}

void pkt_set_fd_out(struct pkt *pkt, int fd)
{
	pkt->fd_out = fd;
}
