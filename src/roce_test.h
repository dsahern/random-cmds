#ifndef _ROCE_TEST_H_
#define _ROCE_TEST_H_

#include "pkt_util.h"

void roce_test(struct pkt *pkt_in, struct pkt *pkt_out[64], unsigned int *outlen);

#endif
