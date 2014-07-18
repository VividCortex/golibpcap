// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkt

/*
#include <netinet/in.h>
#include <netinet/udp.h>
#include "wrappers.h"
*/
import "C"
import (
	"unsafe"
)

// The UdpHdr struct is a wrapper for the udphdr struct in <netinet/udp.h>.
type UdpHdr struct {
	cptr    *C.struct_udphdr // see <netinet/udp.h> struct tcphdr
	Source  uint16           // source port
	Dest    uint16           // destination port
	Len     uint16           // datagram length (header + payload) in bytes
	Check   uint16           // checksum
	payload unsafe.Pointer
}

// With an unsafe.Pointer to the block of C memory NewUdpHdr returns a filled in UdpHdr struct.
func NewUdpHdr(p unsafe.Pointer) (*UdpHdr, unsafe.Pointer) {
	udpHead := &UdpHdr{
		cptr: (*C.struct_udphdr)(p),
	}
	udpHead.Source = uint16(C._ntohs(C._udphdr_source(udpHead.cptr)))
	udpHead.Dest = uint16(C._ntohs(C._udphdr_dest(udpHead.cptr)))
	udpHead.Len = uint16(C._ntohs(C._udphdr_len(udpHead.cptr)))
	udpHead.Check = uint16(C._ntohs(C._udphdr_check(udpHead.cptr)))
	udpHead.payload = unsafe.Pointer(uintptr(p) + 8)
	return udpHead, udpHead.payload
}

// PayloadLen returns the length of the UDP packet's payload in bytes.
func (h *UdpHdr) PayloadLen(pl uint16) uint16 {
	return pl - 8
}
