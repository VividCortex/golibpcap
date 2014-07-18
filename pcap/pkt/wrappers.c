// These wrappers are necessary for Darwin, where these functions are
// defined as preprocessor macros which don't work well with cgo.
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include "wrappers.h"

uint16_t _ntohs(uint16_t n) {
	return ntohs(n);
}

uint32_t _ntohl(uint32_t n) {
	return ntohl(n);
}

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

uint16_t _tcphdr_window(struct tcphdr* h) {
	return h->window;
}

uint16_t _tcphdr_check(struct tcphdr* h) {
	return h->check;
}

uint16_t _tcphdr_urg_ptr(struct tcphdr* h) {
	return h->urg_ptr;
}
