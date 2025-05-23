#include <infiniband/opcode.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <string.h>

#include "roce_hdr.h"
#include "roce_test.h"
#include "logging.h"

static inline bool before(__u32 seq1, __u32 seq2)
{
	return (__s32)(seq1-seq2) < 0;
}
#define after(seq2, seq1)       before(seq1, seq2)

// put packet manipulation logic here
// including dropping packets -- just call pkt_free
// or reordering packets -- hold on to one and send it later

struct qp_md {
	__be32 saddr;
	__be32 daddr;

	struct in6_addr in6_saddr;
	struct in6_addr in6_daddr;
	bool is_v6;

	__u32 qpn;
	unsigned int msg_num;
	unsigned int psn_msg_start;

	bool first_pkt_dropped;
	bool last_pkt_reversed;

	struct pkt *pkt_hold;
};

static struct qp_md qp_all[2];

static struct qp_md *roce_test_get_qp(struct pkt *pkt, __u32 qpn)
{
	struct iphdr *iph = pkt_iph(pkt);
	struct ipv6hdr *ip6h = pkt_ip6h(pkt);
	struct qp_md *qp;
	int i;

	for (i = 0; i < 2; ++i) {
		qp = &qp_all[i];

		if (qp->qpn == qpn) {
			if (iph && !qp->is_v6 &&
			    iph->saddr == qp->saddr &&
			    iph->daddr == qp->daddr)
				return qp;

			if (ip6h && qp->is_v6 &&
			    !memcmp(&ip6h->saddr, &qp->in6_saddr, sizeof(qp->saddr)) &&
			    !memcmp(&ip6h->daddr, &qp->in6_daddr, sizeof(qp->daddr)))
				return qp;
		}

		if (!qp->qpn) {
			if (iph) {
				qp->saddr = iph->saddr;
				qp->daddr = iph->daddr;
			} else if (ip6h) {
				memcpy(&qp->saddr, &ip6h->saddr, sizeof(qp->saddr));
				memcpy(&qp->daddr, &ip6h->daddr, sizeof(qp->daddr));
			} else {
				continue;
			}
			qp->qpn = qpn;
			return qp;
		}
	}

	return NULL;
}

void roce_test(struct pkt *pkt, struct pkt *pkt_out[64], unsigned int *outlen)
{
	struct roce_bth *bth;
	struct qp_md *qp;
	__u32 psn, qpn;

	if (!pkt_is_roce(pkt))
		goto send_pkt;

	pkt_print(pkt);

	bth = pkt_roce_bth(pkt);

	qpn = bth_qpn(bth);
	qp = roce_test_get_qp(pkt, qpn);
	if (!qp)
		goto send_pkt;

	psn = bth_psn(bth);

	switch (bth->opcode) {
	case IBV_OPCODE_RC_SEND_FIRST:
		if (!qp->psn_msg_start || psn > qp->psn_msg_start) {
			qp->msg_num++;
			qp->psn_msg_start = psn;
			log_msg("msn %u at psn %u\n", qp->msg_num, psn);
		}

		if (qp->msg_num == 2 && !qp->first_pkt_dropped) {
			log_msg("Dropping packet with FIRST set\n");
			qp->first_pkt_dropped = true;
			pkt_free(pkt);
			return;
		}

		break;

	case IBV_OPCODE_RC_SEND_MIDDLE:
		if (qp->last_pkt_reversed ||
		    qp->msg_num != 4)
			break;

		log_msg("Holding MIDDLE packet\n");
		if (qp->pkt_hold) {
			log_msg("Sending prior MIDDLE packet\n");
			pkt_out[0] = qp->pkt_hold;
			*outlen = 1;
		}
		qp->pkt_hold = pkt;
		return;

	case IBV_OPCODE_RC_SEND_LAST:
		if (qp->last_pkt_reversed ||
		    qp->msg_num != 4)
			break;

		log_msg("Reversing LAST packet and previous MIDDLE packet\n");
		pkt_out[0] = pkt;
		*outlen = 1;
		if (qp->pkt_hold) {
			pkt_out[1] = qp->pkt_hold;
			*outlen = 2;
		}
		qp->pkt_hold = NULL;
		qp->last_pkt_reversed = true;
		return;
	case IBV_OPCODE_RC_ACKNOWLEDGE:
		// can drop ACK packets as well
		break;
	}

send_pkt:
	pkt_out[0] = pkt;
	*outlen = 1;
}
