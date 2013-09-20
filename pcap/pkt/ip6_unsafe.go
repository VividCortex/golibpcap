// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux,!safe,!appengine

package pkt

/*
#include <netinet/ip6.h>
*/
import "C"
import (
	"net"
	"unsafe"
)

// The Ip6Hdr struct is a wrapper for the ip6_hdrstruct in <netinet/ip6.h>.
type Ip6Hdr struct {
	cptr       *C.struct_ip6_hdr // C pointer to ip6_hdr
	SrcAddr    net.IP            // the sender's ip6 address
	DstAddr    net.IP            // the receiver's ipv6 address
	NextHeader uint8             // next header
	PayloadLen uint16            // payload length
	payload    unsafe.Pointer
}

// With an unsafe.Pointer to the block of C memory NewIp6Hdr returns a filled in Ip6Hdr struct.
func NewIp6Hdr(p unsafe.Pointer) (*Ip6Hdr, unsafe.Pointer) {
	ip6Hdr := &Ip6Hdr{
		cptr: (*C.struct_ip6_hdr)(p),
		// The fixed header of an IPv6 packet consists of its first 40 octets.
		payload: unsafe.Pointer(uintptr(p) + uintptr(40)),
	}
	ip6Hdr.SrcAddr = net.IP(C.GoBytes(unsafe.Pointer(&ip6Hdr.cptr.ip6_src), 16))
	ip6Hdr.DstAddr = net.IP(C.GoBytes(unsafe.Pointer(&ip6Hdr.cptr.ip6_dst), 16))
	u := (*C.struct_ip6_hdrctl)(unsafe.Pointer(&ip6Hdr.cptr.ip6_ctlun))
	ip6Hdr.NextHeader = uint8(u.ip6_un1_nxt)
	ip6Hdr.PayloadLen = uint16(C.ntohs(u.ip6_un1_plen))
	return ip6Hdr, ip6Hdr.payload
}
