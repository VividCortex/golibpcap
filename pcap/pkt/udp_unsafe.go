// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux,!safe,!appengine

package pkt

/*
#include <netinet/in.h>
#include <netinet/udp.h>
*/
import "C"
import (
	"reflect"
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
	udpHead.Source = uint16(C.ntohs(C.uint16_t(udpHead.cptr.source)))
	udpHead.Dest = uint16(C.ntohs(C.uint16_t(udpHead.cptr.dest)))
	udpHead.Len = uint16(C.ntohs(C.uint16_t(udpHead.cptr.len)))
	udpHead.Check = uint16(C.ntohs(C.uint16_t(udpHead.cptr.check)))
	udpHead.payload = unsafe.Pointer(uintptr(p) + 8)
	return udpHead, udpHead.payload
}

// PayloadLen returns the length of the UDP packet's payload in bytes.
func (h *UdpHdr) PayloadLen(pl uint16) uint16 {
	return pl - 8
}

// GetPayloadBytes returns the bytes from the packet's payload.  This is a Go
// slice backed by the C bytes.  The result is that the Go slice uses very
// little extra memory.
func (h *UdpHdr) GetPayloadBytes(pl uint16) []byte {
	l := int(h.PayloadLen(pl))
	if l <= 0 {
		return []byte{}
	}
	var b []byte
	sh := (*reflect.SliceHeader)((unsafe.Pointer(&b)))
	sh.Cap = l
	sh.Len = l
	sh.Data = uintptr(h.payload)
	return b
}
