// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build linux,!safe,!appengine

package pkt

/*
#include "../pcap.h"
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
*/
import "C"
import (
	"time"
	"unsafe"
)

// The Packet struct is a wrapper for the pcap_pkthdr struct in <pcap.h>.
type Packet struct {
	Time    time.Time      // time stamp from the nic
	Caplen  uint32         // length of portion present
	Len     uint32         // length this packet (off wire)
	Headers []Hdr          // Go wrappers for C pkt headers
	buf     unsafe.Pointer // packet data (*C.u_char)
}

// NewPacket returns a parsed and decoded Packet.
// pkthdr_ptr should be a *C.struct_pcap_pkthdr
// buf_ptr should be a *C.u_char
func NewPacket(pkthdr_ptr unsafe.Pointer, buf_ptr unsafe.Pointer) *Packet {
	pkthdr := *(*C.struct_pcap_pkthdr)(pkthdr_ptr)

	p := &Packet{
		Time:    time.Unix(int64(pkthdr.ts.tv_sec), int64(pkthdr.ts.tv_usec)*1000),
		Caplen:  uint32(pkthdr.caplen),
		Len:     uint32(pkthdr.len),
		Headers: make([]Hdr, 3),
		buf:     buf_ptr,
	}
	p.decode()
	return p
}

// Decode decodes the headers of a Packet.
func (p *Packet) decode() {
	ethHdr, buf := NewEthHdr(p.buf)
	p.Headers[LinkLayer] = ethHdr

	switch ethHdr.EtherType {
	case C.ETHERTYPE_IP, 0:
		p.Headers[NetworkLayer], buf = NewIpHdr(buf)
	case C.ETHERTYPE_IPV6:
		p.Headers[NetworkLayer], buf = NewIp6Hdr(buf)
	case C.ETHERTYPE_ARP:
		//TODO(gavaletz) ARP
		return
	default:
		return
	}

	switch p.Headers[NetworkLayer].(InetProtoHdr).Proto() {
	case C.IPPROTO_TCP:
		p.Headers[TransportLayer], _ = NewTcpHdr(buf)
	case C.IPPROTO_UDP:
		p.Headers[TransportLayer], _ = NewUdpHdr(buf)
		return
	case C.IPPROTO_ICMP:
		//TODO(gavaletz) ICMP
		return
	default:
		return
	}
}

type TcpPacket struct {
	DstAddr   []byte
	SrcAddr   []byte
	AckSeq    uint32
	Seq       uint32
	Source    uint16
	Dest      uint16
	Flags     uint16
	Payload   []byte
	Timestamp time.Time
	IsRequest bool
}

func NewPacket2(pkthdr_ptr unsafe.Pointer, buf_ptr unsafe.Pointer) *TcpPacket {
	pkthdr := *(*C.struct_pcap_pkthdr)(pkthdr_ptr)

	// unwrap ethernet packet
	var ethhdr = (*C.struct_ether_header)(buf_ptr)
	var ethtype = uint16(C.ntohs(C.uint16_t(ethhdr.ether_type)))
	if ethtype == 0 {
		// The "cooked" headers have an extra two bytes.
		buf_ptr = unsafe.Pointer(uintptr(buf_ptr) + uintptr(C.ETHER_HDR_LEN) + uintptr(2))
	} else {
		buf_ptr = unsafe.Pointer(uintptr(buf_ptr) + uintptr(C.ETHER_HDR_LEN))
	}

	if ethtype != C.ETHERTYPE_IP && ethtype != 0 {
		return nil
	}

	// unwrap ip packet
	var iphdr = (*C.struct_iphdr)(buf_ptr)
	var iphdrlen = *(*byte)(buf_ptr) & 0x0F
	var paylen = uint16(C.ntohs(C.uint16_t(iphdr.tot_len))) - uint16(iphdrlen*4)

	buf_ptr = unsafe.Pointer(uintptr(buf_ptr) + uintptr(iphdrlen*4))

	if uint8(iphdr.protocol) != C.IPPROTO_TCP {
		return nil
	}

	// unwrap tcp packet
	var tcphdr = (*C.struct_tcphdr)(buf_ptr)
	var dataoffset = *(*byte)(unsafe.Pointer(uintptr(buf_ptr) + uintptr(12))) >> 4

	return &TcpPacket{
		DstAddr:   C.GoBytes(unsafe.Pointer(&iphdr.daddr), 4),
		SrcAddr:   C.GoBytes(unsafe.Pointer(&iphdr.saddr), 4),
		AckSeq:    uint32(C.ntohl(C.uint32_t(tcphdr.ack_seq))),
		Seq:       uint32(C.ntohl(C.uint32_t(tcphdr.seq))),
		Source:    uint16(C.ntohs(C.uint16_t(tcphdr.source))),
		Dest:      uint16(C.ntohs(C.uint16_t(tcphdr.dest))),
		Flags:     uint16(C.ntohs(C.uint16_t(*(*uint16)(unsafe.Pointer(uintptr(buf_ptr) + uintptr(12)))))) & uint16(0x01FF),
		Payload:   C.GoBytes(unsafe.Pointer(uintptr(buf_ptr)+uintptr(dataoffset*4)), C.int(paylen-uint16(dataoffset*4))),
		Timestamp: time.Unix(int64(pkthdr.ts.tv_sec), int64(pkthdr.ts.tv_usec)*1000),
		IsRequest: false,
	}
}
