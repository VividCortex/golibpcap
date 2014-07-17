// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin freebsd

package pkt

/*
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include "wrappers.h"
*/
import "C"
import (
	"net"
	"unsafe"
)

// The IpHdr struct is a wrapper for the iphdr struct in <netinet/ip.h>.
type IpHdr struct {
	cptr       *C.struct_ip
	Ihl        uint8  // header length (32bit words)
	Version    uint8  // version
	SrcAddr    net.IP // source address
	DstAddr    net.IP // dest address
	Protocol   uint8  // protocol
	TotLen     uint16 // total length (bytes)
	PayloadLen uint16 // payload length (bytes)
	payload    unsafe.Pointer
}

// With an unsafe.Pointer to the block of C memory NewIpHdr returns a filled in IpHdr struct.
func NewIpHdr(p unsafe.Pointer) (*IpHdr, unsafe.Pointer) {
	iphdr := &IpHdr{
		cptr: (*C.struct_ip)(p),
		// Since cgo does not provide access to bit fields in a struct
		// we take the first octet and then mask the unneeded bits.
		Ihl: *(*byte)(p) & 0x0F,
		// Since cgo does not provide access to bit fields in a struct
		// we take the first octet and then shift out the unneeded bits.
		Version: *(*byte)(p) >> 4,
	}
	iphdr.SrcAddr = net.IP(C.GoBytes(unsafe.Pointer(&iphdr.cptr.ip_src.s_addr), 4))
	iphdr.DstAddr = net.IP(C.GoBytes(unsafe.Pointer(&iphdr.cptr.ip_dst.s_addr), 4))
	iphdr.Protocol = uint8(iphdr.cptr.ip_p)
	iphdr.TotLen = uint16(C._ntohs(C.uint16_t(iphdr.cptr.ip_len)))
	iphdr.PayloadLen = iphdr.TotLen - uint16(iphdr.Ihl*4)
	iphdr.payload = unsafe.Pointer(uintptr(p) + uintptr(iphdr.Ihl*4))
	return iphdr, iphdr.payload
}

// Id returns the identification of the IP flow.
func (h *IpHdr) Id() uint16 {
	return uint16(C._ntohs(C.uint16_t(h.cptr.ip_id)))
}
