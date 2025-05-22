#ifndef _PKT_H_
#define _PKT_H_

#include <linux/types.h>
#include <stdbool.h>

struct enf_bth {
	__u8    ver:2,
		timestamp_present:1,  /* MoTCP only */
		more_segments:1,
		rtr:1,
		rtr_ack:1,
		rsvd:2;
	__u8    opcode;     /* RoCE opcode */
	__be16  msn;        /* message seq number */
	__be32  mbo_seg;    /* 24b message byte offset; 8b segment */
	__be32  icrc;
	__be32  timestamp;            /* MoTCP only */
	__be32  timestamp_echo;       /* MoTCP only */
};

/* pkt is opaque to users */
struct pkt;

int pkt_read(int fd, unsigned int max_len, struct pkt **ppkt);
int pkt_write(struct pkt *pkt);
int pkt_write_and_release(struct pkt *pkt);

void pkt_free(struct pkt *pkt);
void pkt_print(const struct pkt *pkt);

bool pkt_is_roce(struct pkt *pkt);
bool pkt_is_motcp(struct pkt *pkt);

struct iphdr *pkt_iph(struct pkt *pkt);
struct ipv6hdr *pkt_ip6h(struct pkt *pkt);

struct roce_bth *pkt_roce_bth(struct pkt *pkt);
struct enf_bth *pkt_motcp_bth(struct pkt *pkt);

void pkt_set_fd_out(struct pkt *pkt, int fd);
#endif
