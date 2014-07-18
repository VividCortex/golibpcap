#ifndef WRAPPERS_H
#define WRAPPERS_H

#include <netinet/tcp.h>
#include <netinet/udp.h>

uint16_t _ntohs(uint16_t);
uint32_t _ntohl(uint32_t);

uint16_t _tcphdr_source(struct tcphdr*);
uint16_t _tcphdr_dest(struct tcphdr*);
uint32_t _tcphdr_seq(struct tcphdr*);
uint32_t _tcphdr_ack_seq(struct tcphdr*);
uint16_t _tcphdr_window(struct tcphdr*);
uint16_t _tcphdr_check(struct tcphdr*);
uint16_t _tcphdr_urg_ptr(struct tcphdr*);

uint16_t _udphdr_source(struct udphdr*);
uint16_t _udphdr_dest(struct udphdr*);
uint16_t _udphdr_check(struct udphdr*);
uint16_t _udphdr_len(struct udphdr*);

#endif
