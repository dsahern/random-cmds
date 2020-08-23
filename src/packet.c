// SPDX-License-Identifier: GPL-2.0
/* Functions to parse and pretty print packet headers
 *
 * David Ahern <dsahern@gmail.com>
 */
#include <linux/types.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/icmpv6.h>
#include <linux/ipv6.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "packet.h"
#include "str_utils.h"

#define NDISC_ROUTER_SOLICITATION       133
#define NDISC_ROUTER_ADVERTISEMENT      134
#define NDISC_NEIGHBOUR_SOLICITATION    135
#define NDISC_NEIGHBOUR_ADVERTISEMENT   136

static int parse_tcp(struct flow_tcp *fl_tcp, const __u8 *data, __u32 len)
{
	const struct tcphdr *tcph;

	if (len < sizeof(*tcph))
		return -1;

	tcph = (struct tcphdr *)data;

	fl_tcp->sport = ntohs(tcph->source);
	fl_tcp->dport = ntohs(tcph->dest);

	if (tcph->syn)
		fl_tcp->syn = 1;
	if (tcph->ack)
		fl_tcp->ack = 1;
	if (tcph->fin)
		fl_tcp->fin = 1;
	if (tcph->rst)
		fl_tcp->rst = 1;

	return 0;
}

static int parse_udp(struct flow_udp *fl_udp, const __u8 *data, __u32 len)
{
	const struct udphdr *udph;

	if (len < sizeof(*udph))
		return -1;

	udph = (struct udphdr *)data;

	fl_udp->sport = ntohs(udph->source);
	fl_udp->dport = ntohs(udph->dest);

	return 0;
}

static int parse_icmpv6(struct flow_icmp6 *fli, const __u8 *data, __u32 len)
{
	const struct icmp6hdr *icmp6;

	if (len < sizeof(*icmp6))
		return -1;

	icmp6 = (const struct icmp6hdr *)data;
	fli->icmp6_type = icmp6->icmp6_type;
	fli->icmp6_code = icmp6->icmp6_code;

	return 0;
}

static int parse_transport(struct flow_transport *flt,
			   const __u8 *data, __u32 len)
{

	flt->len = len;
	switch(flt->proto) {
	case IPPROTO_TCP:
		return parse_tcp(&flt->tcp, data, len);
	case IPPROTO_UDP:
		return parse_udp(&flt->udp, data, len);
	case IPPROTO_ICMPV6:
		return parse_icmpv6(&flt->icmp6, data, len);
	}

	return 0;
}

static int parse_ipv6(struct flow_ip6 *fl6, const __u8 *data, __u32 len)
{
	const struct ipv6hdr *ip6h = (const struct ipv6hdr *)data;

	if (len < sizeof(*ip6h))
		return -1;

	fl6->saddr = ip6h->saddr;
	fl6->daddr = ip6h->daddr;
	fl6->len = ntohs(ip6h->payload_len);
	fl6->trans.proto = ip6h->nexthdr;

	len -= sizeof(*ip6h);
	data += sizeof(*ip6h);

	return parse_transport(&fl6->trans, data, len);
}

static int parse_ipv4(struct flow_ip4 *fl4, const __u8 *data, __u32 len)
{
	const struct iphdr *iph = (const struct iphdr *)data;
	unsigned int hlen;

	if (len < sizeof(*iph))
		return -1;

	hlen = iph->ihl << 2;

	fl4->saddr = iph->saddr;
	fl4->daddr = iph->daddr;
	fl4->len = hlen;
	fl4->trans.proto = iph->protocol;

	len -= hlen;
	data += hlen;

	return parse_transport(&fl4->trans, data, len);
}

static int parse_arp(struct flow_arp *fla, const __u8 *data, __u32 len)
{
	const struct arphdr *arph = (const struct arphdr *)data;
	struct arpdata *arp_data;

	if (len < sizeof(*arph))
		return -1;

	if (ntohs(arph->ar_hrd) != ARPHRD_ETHER || arph->ar_hln != ETH_ALEN ||
	    arph->ar_pro != htons(ETH_P_IP) || arph->ar_pln != 4)
		return -1;

	fla->op = ntohs(arph->ar_op);

	len -= sizeof(*arph);
	if (len < sizeof(*arp_data))
		return -1;

	arp_data = (struct arpdata *)(arph + 1);
	memcpy(&fla->data, arp_data, sizeof(fla->data));

	return 0;
}

static int parse_pkt(struct flow *flow, const __u8 *data, int len)
{
	const struct ethhdr *eth = (const struct ethhdr *)data;
	__u16 proto = ntohs(eth->h_proto);
	unsigned int hlen = sizeof(*eth);

	if (len < hlen)
		return -1;

	memcpy(flow->dmac, eth->h_dest, ETH_ALEN);
	memcpy(flow->smac, eth->h_source, ETH_ALEN);
	flow->len = len;

	if (proto == ETH_P_8021Q) {
		const struct vlan_hdr *vhdr;

		vhdr = (const struct vlan_hdr *)(data + sizeof(*eth));

		hlen += sizeof(struct vlan_hdr);
		if (len < hlen)
			return -1;

		flow->has_vlan = true;
		flow->vlan.outer_vlan_TCI = ntohs(vhdr->h_vlan_TCI);
		proto = ntohs(vhdr->h_vlan_encapsulated_proto);
	}

	data += hlen;
	len -= hlen;

	flow->proto = proto;
	switch(proto) {
	case ETH_P_ARP:
		return parse_arp(&flow->arp, data, len);
	case ETH_P_IP:
		return parse_ipv4(&flow->ip4, data, len);
	case ETH_P_IPV6:
		return parse_ipv6(&flow->ip6, data, len);
	}

	return 0;
}

static void print_tcp(const struct flow_tcp *fl, const char *src,
		      const char *dst)
{
	printf("  %s/%d > %s/%d TCP",
		src, fl->sport, dst, fl->dport);

	if (fl->syn)
		printf(" SYN");
	if (fl->ack)
		printf(" ACK");
	if (fl->fin)
		printf(" FIN");
	if (fl->rst)
		printf(" RST");
}

static void print_udp(const struct flow_udp *fl, const char *src,
		      const char *dst)
{
	printf("  %s/%d > %s/%d UDP",
		src, fl->sport, dst, fl->dport);
}

static void print_icmp6(const struct flow_icmp6 *fli, const char *src,
			const char *dst)
{
	printf("  %s > %s ICMP ", src, dst);
	switch(fli->icmp6_type) {
	case NDISC_ROUTER_SOLICITATION:
		printf("router solicitation");
		break;
	case NDISC_ROUTER_ADVERTISEMENT:
		printf("router advertisement");
		break;
	case NDISC_NEIGHBOUR_SOLICITATION:
		printf("neighbor solicitation");
		break;
	case NDISC_NEIGHBOUR_ADVERTISEMENT:
		printf("neighbor advertisement");
		break;
	case ICMPV6_ECHO_REQUEST:
		printf("echo request");
		break;
	case ICMPV6_ECHO_REPLY:
		printf("echo reply");
		break;
	default:
		printf("unknown %u/%u", fli->icmp6_type, fli->icmp6_code);
	}
}

static void print_transport(const struct flow_transport *fl,
			    const char *src, const char *dst)
{
	switch(fl->proto) {
	case IPPROTO_TCP:
		print_tcp(&fl->tcp, src, dst);
		break;
	case IPPROTO_UDP:
		print_udp(&fl->udp, src, dst);
		break;
	case IPPROTO_VRRP:
		printf("  %s > %s VRRP", src, dst);
		break;
	case IPPROTO_ICMPV6:
		print_icmp6(&fl->icmp6, src, dst);
		break;
	case IPPROTO_HOPOPTS:
		printf("  %s > %s HBH", src, dst);
		break;
	default:
		printf("  protocol %u: %s > %s",
			fl->proto, src, dst);
	}
	printf(" length %u", fl->len);
}

static void print_ipv6(const struct flow_ip6 *fl6)
{
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &fl6->saddr, src, sizeof(src));
	inet_ntop(AF_INET6, &fl6->daddr, dst, sizeof(dst));

	print_transport(&fl6->trans, src, dst);
	printf("\n");
}

static void print_ipv4(const struct flow_ip4 *fl4)
{
	char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &fl4->saddr, src, sizeof(src));
	inet_ntop(AF_INET, &fl4->daddr, dst, sizeof(dst));

	print_transport(&fl4->trans, src, dst);
	printf("\n");
}

static void print_arphdr(const struct flow_arp *fla)
{
	char addr[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &fla->data.ar_sip, addr, sizeof(addr));
	printf("sender: %s ", addr);
	print_mac(fla->data.ar_sha, false);

	inet_ntop(AF_INET, &fla->data.ar_tip, addr, sizeof(addr));
	printf(" target: %s ", addr);
	print_mac(fla->data.ar_tha, false);
}

static void print_arp(const struct flow_arp *fla)
{
	printf("    ");

	switch(fla->op) {
	case ARPOP_REQUEST:
		printf("arp request: ");
		break;
	case ARPOP_REPLY:
		printf("arp reply: ");
		break;
	case ARPOP_RREQUEST:
		printf("rarp request: ");
		break;
	case ARPOP_RREPLY:
		printf("rarp reply: ");
		break;
	default:
		printf("arp op %x: ", fla->op);
		break;
	}
	print_arphdr(fla);
	printf("\n");
}

void print_flow(const struct flow *fl)
{
	print_mac(fl->smac, false);
	printf(" > ");
	print_mac(fl->dmac, false);
	printf(" length %u:", fl->len);

	if (fl->has_vlan) {
		__u16 vlan, prio;

		vlan = fl->vlan.outer_vlan_TCI & VLAN_VID_MASK;
		printf(" vlan %u", vlan);

		prio = (fl->vlan.outer_vlan_TCI & VLAN_PRIO_MASK);
		prio >>= VLAN_PRIO_SHIFT;
		if (prio)
			printf(" prio %u", prio);
	}

	switch(fl->proto) {
	case ETH_P_ARP:
		print_arp(&fl->arp);
		break;
	case ETH_P_IP:
		print_ipv4(&fl->ip4);
		break;
	case ETH_P_IPV6:
		print_ipv6(&fl->ip6);
		break;
	case ETH_P_LLDP:
		printf("    LLDP\n");
		break;
	default:
		printf("    ethernet protocol %x\n", fl->proto);
	}
}

void print_pkt(const void *data, int len)
{
	struct flow fl = {};

	if (parse_pkt(&fl, data, len))
		printf("*** failed to parse packet ***\n");
	else
		print_flow(&fl);
}
