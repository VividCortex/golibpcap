// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !safe,!appengine

package pkt

/*
#include <netinet/ip.h>
#include <netinet/tcp.h>
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

func unwrapHeaders(packet TcpPacket, iphdr *C.struct_iphdr, tcphdr *C.struct_tcphdr) TcpPacket {
	packet.DstAddr = uint32(iphdr.daddr)
	packet.SrcAddr = uint32(iphdr.saddr)
	packet.AckSeq = uint32(tcphdr.ack_seq)
	packet.Seq = uint32(tcphdr.seq)
	packet.Source = uint16(tcphdr.source)
	packet.Dest = uint16(tcphdr.dest)

	return packet
}
