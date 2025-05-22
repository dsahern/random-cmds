#ifndef _TESTS_H_
#define _TESTS_H_

#include "pkt.h"

void roce_test(struct pkt *pkt_in, struct pkt *pkt_out[64], unsigned int *outlen);

#endif
