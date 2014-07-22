// These wrappers are necessary for Darwin and Ubuntu 14.04,
// where the implementations of certain things don't work
// well with cgo.
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "wrappers.h"

uint16_t _ntohs(uint16_t n) {
	return ntohs(n);
}

uint32_t _ntohl(uint32_t n) {
	return ntohl(n);
}

#ifdef __linux

uint16_t _tcphdr_source(struct tcphdr* h) {
	return h->source;
}

uint16_t _tcphdr_dest(struct tcphdr* h) {
	return h->dest;
}

uint32_t _tcphdr_seq(struct tcphdr* h) {
	return h->seq;
}

uint32_t _tcphdr_ack_seq(struct tcphdr* h) {
	return h->ack_seq;
}

uint16_t _tcphdr_source_ntohs(struct tcphdr* h) {
	return ntohs(h->source);
}

uint16_t _tcphdr_dest_ntohs(struct tcphdr* h) {
	return ntohs(h->dest);
}

uint32_t _tcphdr_seq_ntohl(struct tcphdr* h) {
	return ntohl(h->seq);
}

uint32_t _tcphdr_ack_seq_ntohl(struct tcphdr* h) {
	return ntohl(h->ack_seq);
}

uint16_t _tcphdr_window_ntohs(struct tcphdr* h) {
	return ntohs(h->window);
}

uint16_t _tcphdr_check_ntohs(struct tcphdr* h) {
	return ntohs(h->check);
}

uint16_t _tcphdr_urg_ptr_ntohs(struct tcphdr* h) {
	return ntohs(h->urg_ptr);
}

uint16_t _udphdr_source_ntohs(struct udphdr* h) {
	return ntohs(h->source);
}

uint16_t _udphdr_dest_ntohs(struct udphdr* h) {
	return ntohs(h->dest);
}

uint16_t _udphdr_check_ntohs(struct udphdr* h) {
	return ntohs(h->check);
}

uint16_t _udphdr_len_ntohs(struct udphdr* h) {
	return ntohs(h->len);
}

#endif
