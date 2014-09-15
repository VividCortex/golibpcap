// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkt

/*
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "wrappers.h"
*/
import "C"
import (
	"unsafe"
)

func getIphdr(buf_ptr unsafe.Pointer) *C.struct_iphdr {
	return (*C.struct_iphdr)(buf_ptr)
}

func getPaylen(iphdr *C.struct_iphdr) uint16 {
	return uint16(iphdr.tot_len)
}

func getProtocol(iphdr *C.struct_iphdr) uint8 {
	return uint8(iphdr.protocol)
}
