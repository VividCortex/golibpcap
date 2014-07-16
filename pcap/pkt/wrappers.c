// These wrappers are necessary for Darwin, where these functions are
// defined as preprocessor macros which don't work well with cgo.
#include <arpa/inet.h>
#include "wrappers.h"

uint16_t _ntohs(uint16_t n) {
	return ntohs(n);
}

uint32_t _ntohl(uint32_t n) {
	return ntohl(n);
}
