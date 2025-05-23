#ifndef _ROCE_HDR_H
#define _ROCE_HDR_H

#include <linux/types.h>
#include <arpa/inet.h>

#define ROCE_V2_UDP_DPORT      4791

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

struct roce_aeth {
	__be32                  smsn;
};

#define AETH_SYN_MASK		0xff000000
#define AETH_MSN_MASK		0x00ffffff

#define AETH_TYPE_MASK		0xe0
#define AETH_ACK		0x00
#define AETH_RNR_NAK		0x20
#define AETH_NAK		0x60
#define AETH_ACK_UNLIMITED      0x1f
#define AETH_NAK_PSN_SEQ_ERROR  0x60
#define AETH_NAK_INVALID_REQ    0x61
#define AETH_NAK_REM_ACC_ERR    0x62
#define AETH_NAK_REM_OP_ERR     0x63

static inline __u8 __aeth_syn(struct roce_aeth *aeth)
{
        return (AETH_SYN_MASK & ntohl(aeth->smsn)) >> 24;
}

#endif /* _ROCE_HDR_H */
