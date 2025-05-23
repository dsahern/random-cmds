#ifndef _PKT_H_
#define _PKT_H_

#include <linux/types.h>
#include <stdbool.h>

/* pkt is opaque to users */
struct pkt;

int pkt_read(int fd, unsigned int max_len, struct pkt **ppkt);
int pkt_write(struct pkt *pkt);
int pkt_write_and_release(struct pkt *pkt);

struct pkt *pkt_alloc(unsigned int max_len);
void pkt_free(struct pkt *pkt);
void pkt_print(const struct pkt *pkt);

bool pkt_is_roce(struct pkt *pkt);
bool pkt_is_motcp(struct pkt *pkt);

struct iphdr *pkt_iph(struct pkt *pkt);
struct ipv6hdr *pkt_ip6h(struct pkt *pkt);

struct roce_bth *pkt_roce_bth(struct pkt *pkt);
struct enf_bth *pkt_motcp_bth(struct pkt *pkt);

unsigned char *pkt_payload(struct pkt *pkt);

void pkt_set_fd_out(struct pkt *pkt, int fd);
#endif
