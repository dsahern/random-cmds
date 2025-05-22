#ifndef _ROCE_HDR_H
#define _ROCE_HDR_H

#include <linux/types.h>
#include <arpa/inet.h>

struct roce_bth {
	__u8			opcode;
	__u8			flags;
	__be16			pkey;
	__be32			qpn;
	__be32			apsn;
};

#define BTH_QPN_MASK            (0x00ffffff)
#define BTH_PSN_MASK            (0x00ffffff)
#define BTH_ACK_MASK            (0x80000000)

static inline __u32 bth_qpn(struct roce_bth *bth)
{
	return BTH_QPN_MASK & ntohl(bth->qpn);
}

static inline int bth_ack(struct roce_bth *bth)
{
	return 0 != (htonl(BTH_ACK_MASK) & bth->apsn);
}

static inline __u32 bth_psn(struct roce_bth *bth)
{
	return BTH_PSN_MASK & ntohl(bth->apsn);
}

#endif /* _ROCE_HDR_H */
