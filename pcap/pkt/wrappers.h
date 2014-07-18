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

uint16_t _tcphdr_source_ntohs(struct tcphdr*);
uint16_t _tcphdr_dest_ntohs(struct tcphdr*);
uint32_t _tcphdr_seq_ntohl(struct tcphdr*);
uint32_t _tcphdr_ack_seq_ntohl(struct tcphdr*);
uint16_t _tcphdr_window_ntohs(struct tcphdr*);
uint16_t _tcphdr_check_ntohs(struct tcphdr*);
uint16_t _tcphdr_urg_ptr_ntohs(struct tcphdr*);

uint16_t _udphdr_source_ntohs(struct udphdr*);
uint16_t _udphdr_dest_ntohs(struct udphdr*);
uint16_t _udphdr_check_ntohs(struct udphdr*);
uint16_t _udphdr_len_ntohs(struct udphdr*);

#endif
