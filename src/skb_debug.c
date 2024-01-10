#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <net/ndisc.h>
#include <net/ipv6.h>

#ifndef ETH_P_LLDP
#define ETH_P_LLDP 0x88CC
#endif

static void skb_dump_data(const struct sk_buff *skb, int maxlen)
{
	int i, j;
	char buf[256], bytes[10];
	int dumplen = (maxlen < skb->len ? maxlen : skb->len);

	if (dumplen && !is_power_of_2(dumplen))
		dumplen--;

	buf[0] = 0;
	pr_info("skb start\n");
	for (i = 0, j = 0; i < dumplen; i+=2, ++j) {
		sprintf(bytes ,"%2.2x%2.2x ",
			    *(uint8_t *)(skb->data+i), *(uint8_t *)(skb->data+i+1));
		strcat(buf, bytes);
		if (j == 7) {
			j = -1;
			pr_info("%s\n", buf);
			buf[0] = 0;
		}
	}
	if (buf[0])
			pr_info("%s\n", buf);
	pr_info("skb done\n");
}

static void skb_print_ipv4(const struct sk_buff *skb, const char *desc)
{
	const struct iphdr *iph = ip_hdr(skb);
	const struct tcphdr *tcph;
	const struct udphdr *udph;
	const struct icmphdr *icmph;
	unsigned int hlen;

	if (skb->len < sizeof(*iph)) {
		pr_info("%s: packet too small for ipv4 header\n", desc);
		return;
	}

	hlen = iph->ihl << 2;
	switch(iph->protocol) {
	case IPPROTO_TCP:
		if (skb->len < hlen + sizeof(*tcph)) {
			pr_info("%s: ipv4 packet too small for tcp header\n", desc);
			return;
		}

		tcph = (struct tcphdr *) (skb->data + hlen);
		pr_info("%s: TCP packet: %s: src=%pI4/%d -> dst=%pI4/%d\n",
			desc, skb->dev->name, &iph->saddr, ntohs(tcph->source),
			&iph->daddr, ntohs(tcph->dest));
		break;

	case IPPROTO_UDP:
		if (skb->len < hlen + sizeof(*udph)) {
			pr_info("%s: ipv4 packet too small for udp header\n", desc);
			return;
		}

		udph = (struct udphdr *) (skb->data + hlen);
		pr_info("%s: UDP packet: %s: src=%pI4/%d -> dst=%pI4/%d\n",
			desc, skb->dev->name, &iph->saddr, ntohs(udph->source),
			&iph->daddr, ntohs(udph->dest));
		break;

	case IPPROTO_ICMP:
		if (skb->len < hlen + sizeof(*icmph)) {
			pr_info("%s: ipv4 packet too small for icmp header\n", desc);
			return;
		}

		icmph = (struct icmphdr *) (skb->data + hlen);
		pr_info("%s: ICMP packet: %s: %d/%d: src=%pI4 -> dst=%pI4\n",
			desc, skb->dev->name, icmph->type, icmph->code,
			&iph->saddr, &iph->daddr);
		break;

	default:
		pr_info("%s: protocol 0x%x packet: %s: src=%pI4 -> dst=%pI4\n",
			desc, ntohs(iph->protocol), skb->dev->name,
			&iph->saddr, &iph->daddr);
		skb_dump_data(skb, 80);
	}
	pr_info("%s: skb_debug done\n", desc);

	return;
}

static void skb_print_icmpv6(const struct sk_buff *skb,
			     const struct ipv6hdr *ipv6h,
			     const struct icmp6hdr *icmph,
			     const char *desc)
{
	u8 type = icmph->icmp6_type;

	switch(type) {
	case ICMPV6_ECHO_REQUEST:
		pr_info("%s: ICMPv6 echo request: %s: src=%pI6c -> dst=%pI6c\n",
			desc, skb->dev->name, &ipv6h->saddr, &ipv6h->daddr);
		break;

	case ICMPV6_ECHO_REPLY:
		pr_info("%s: ICMPv6 echo reply: %s: src=%pI6c -> dst=%pI6c\n",
			desc, skb->dev->name, &ipv6h->saddr, &ipv6h->daddr);
		break;


        case NDISC_ROUTER_SOLICITATION:
        case NDISC_ROUTER_ADVERTISEMENT:
		pr_info("%s: ICMPv6 router packet: %s: %d/%d: src=%pI6c -> dst=%pI6c\n",
			desc, skb->dev->name, icmph->icmp6_type, icmph->icmp6_code,
			&ipv6h->saddr, &ipv6h->daddr);
		break;

        case NDISC_NEIGHBOUR_SOLICITATION:
        case NDISC_NEIGHBOUR_ADVERTISEMENT:
        case NDISC_REDIRECT:
		pr_info("%s: ICMPv6 neighbor packet: %s: %d/%d: src=%pI6c -> dst=%pI6c\n",
			desc, skb->dev->name, icmph->icmp6_type, icmph->icmp6_code,
			&ipv6h->saddr, &ipv6h->daddr);
		break;

	default:
		pr_info("%s: ICMPv6 packet: %s: %d/%d: src=%pI6c -> dst=%pI6c\n",
			desc, skb->dev->name, icmph->icmp6_type, icmph->icmp6_code,
			&ipv6h->saddr, &ipv6h->daddr);
	}
}

static void skb_print_ipv6(const struct sk_buff *skb, const char *desc)
{
	const struct ipv6hdr *ipv6h = ipv6_hdr(skb);
	const struct tcphdr *tcph;
	const struct udphdr *udph;
	const struct icmp6hdr *icmph;
	unsigned int hlen = sizeof(*ipv6h);
	void *p;

	if (skb->len < hlen) {
		pr_info("%s: packet too small for ipv6 header\n", desc);
		return;
	}

	p = skb->data + sizeof(*ipv6h);
	switch(ipv6h->nexthdr) {
	case NEXTHDR_TCP:
		if (skb->len < hlen + sizeof(*tcph)) {
			pr_info("%s: ipv6 packet too small for tcp header\n", desc);
			return;
		}

		tcph = (struct tcphdr *) p;
		pr_info("%s: TCP packet: %s: src=%pI6c/%d -> dst=%pI6c/%d\n",
			desc, skb->dev->name, &ipv6h->saddr, ntohs(tcph->source),
			&ipv6h->daddr, ntohs(tcph->dest));
		break;

	case NEXTHDR_UDP:
		if (skb->len < hlen + sizeof(*udph)) {
			pr_info("%s: ipv6 packet too small for udp header\n", desc);
			return;
		}

		udph = (struct udphdr *) p;
		pr_info("%s: UDP packet: %s: src=%pI6c/%d -> dst=%pI6c/%d\n",
			desc, skb->dev->name, &ipv6h->saddr, ntohs(udph->source),
			&ipv6h->daddr, ntohs(udph->dest));
		break;

	case NEXTHDR_ICMP:
		if (skb->len < hlen + sizeof(*icmph)) {
			pr_info("%s: ipv6 packet too small for icmp header\n", desc);
			return;
		}
		icmph = (struct icmp6hdr *) p;
		skb_print_icmpv6(skb, ipv6h, icmph, desc);
		break;


	default:
		pr_info("%s: IPv6 packet: %s: next protocol %d src=%pI6c -> dst=%pI6c\n",
			desc, skb->dev->name, ipv6h->nexthdr,
			&ipv6h->saddr, &ipv6h->daddr);
		skb_dump_data(skb, 80);
	}

	pr_info("%s: skb_debug done\n", desc);

	return;
}

void skb_print_pkt(const struct sk_buff *skb, const char *desc)
{
	switch(ntohs(skb->protocol)) {
	case ETH_P_ARP:
		pr_info("%s: arp packet\n", desc);
		skb_dump_data(skb, 80);
		break;

	case ETH_P_LLDP:
		pr_info("%s: lldp packet\n", desc);
		skb_dump_data(skb, 80);
		break;

	case ETH_P_IP:
		skb_print_ipv4(skb, desc);
		break;

	case ETH_P_IPV6:
		skb_print_ipv6(skb, desc);
		break;

	default:
		pr_info("%s: unknown packet, protocol %x\n",
			desc, ntohs(skb->protocol));
		skb_dump_data(skb, 80);
	}
}
