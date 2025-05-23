#ifndef _MOTCP_HDR_H_
#define _MOTCP_HDR_H_

#include <linux/types.h>

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

/* size of the TCP option when using the experimental kind */
#define TCPOLEN_EXP_ENF_BTH     (4 + sizeof(struct enf_bth))
#define TCPOPT_EXP_ENF_BTH_EXID         0xEFAB

#define TCPOPT_NOP              1       /* Padding */
#define TCPOPT_EOL              0       /* End of options */
#define TCPOPT_EXP              254     /* Experimental */

#endif
