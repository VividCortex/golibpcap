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

func unwrapHeaders(packet TcpPacket, iphdr *C.struct_iphdr, tcphdr *C.struct_tcphdr) TcpPacket {
	packet.DstAddr = uint32(iphdr.daddr)
	packet.SrcAddr = uint32(iphdr.saddr)
	packet.AckSeq = uint32(C._tcphdr_ack_seq(tcphdr))
	packet.Seq = uint32(C._tcphdr_seq(tcphdr))
	packet.Source = uint16(C._tcphdr_source(tcphdr))
	packet.Dest = uint16(C._tcphdr_dest(tcphdr))

	return packet
}
