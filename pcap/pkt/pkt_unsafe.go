// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !safe,!appengine

package pkt

/*
#include "../pcap.h"
#include "../pcap/bpf.h"
#include "../pcap/sll.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>

// linux cooked header
struct gen_sll {
	u_int16_t pkt_type;
	u_int16_t addr_type;
	u_int16_t addr_len;
	u_int8_t addr[8];
	u_int16_t protocol;
};

// generic little-endian tcphdr
struct gen_tcphdr {
	u_int16_t source;
	u_int16_t dest;
	u_int32_t seq;
	u_int32_t ack_seq;
	u_int16_t flags;
	u_int16_t window;
	u_int16_t check;
	u_int16_t urg_ptr;
};

// generic little-endian iphdr
struct gen_iphdr {
	u_int8_t misc;
	u_int8_t tos;
	u_int16_t len;
	u_int16_t id;
	u_int16_t off;
	u_int8_t ttl;
	u_int8_t protocol;
	u_int16_t checksum;
	u_int32_t src_addr;
	u_int32_t dst_addr;
};

// generic little-endian ip6hdr
struct gen_ip6hdr {
	u_int32_t misc; // 4 bits version, 8 traffic class, 20 flow label
	u_int16_t len;
	u_int8_t next_hdr;
	u_int8_t ttl;
	u_int32_t src_addr0;
	u_int32_t src_addr1;
	u_int32_t src_addr2;
	u_int32_t src_addr3;
	u_int32_t dst_addr0;
	u_int32_t dst_addr1;
	u_int32_t dst_addr2;
	u_int32_t dst_addr3;
};

*/
import "C"
import (
	"encoding/hex"
	"fmt"
	"reflect"
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
	DstAddr0  uint32 // IPv4 uses only this one, others are 0
	DstAddr1  uint32
	DstAddr2  uint32
	DstAddr3  uint32
	SrcAddr0  uint32 // IPv4 uses only this one, others are 0
	SrcAddr1  uint32
	SrcAddr2  uint32
	SrcAddr3  uint32
	AckSeq    uint32
	Seq       uint32
	Source    uint16
	Dest      uint16
	Flags     uint16
	Payload   []byte
	Timestamp time.Time
	IsRequest bool
	Saved     bool
}

func (this *TcpPacket) Save() {
	if !this.Saved {
		var dcopy = make([]byte, len(this.Payload))
		copy(dcopy, this.Payload)
		this.Payload = dcopy
		this.Saved = true
	}
}

func (this *TcpPacket) Clone() *TcpPacket {
	dupe := *this
	if !this.Saved {
		dupe.Payload = append([]byte{}, this.Payload...)
		dupe.Saved = true
	}
	return &dupe
}

// debugging aid
func dumpBuf(pbuf unsafe.Pointer, maxlen int) string {
	sbuf := make([]byte, 1)
	var plA, plH string
	for i := 0; i < maxlen; i++ {
		c := *(*byte)(unsafe.Pointer(uintptr(pbuf) + uintptr(i)))
		if c >= 32 && c <= 126 {
			plA += string(c)
		} else {
			plA += "."
		}
		sbuf[0] = c
		plH += hex.EncodeToString(sbuf[:]) + " "
	}
	return fmt.Sprintf("[%d] [%s] [ %s]", maxlen, plA, plH)
}

// FIXME: we are assuming little endian arch... everywhere
const ETHERTYPE_IP = C.ETHERTYPE_IP>>8 | C.ETHERTYPE_IP&0xFF<<8
const ETHERTYPE_IPV6 = C.ETHERTYPE_IPV6>>8 | C.ETHERTYPE_IPV6&0xFF<<8
const LINUX_SLL_IPV6 = 0xDD86 // magic
const IPV6_HEADER_LEN = 40    // fixed, unlike IPv4's

// NewPacket2 takes a libpcap buffer and extracts TCP/IPv{4,6} packets into
// a TcpPacket without creating additional data in the heap. If the recipient of
// this packet needs to keep a copy of it, it should call func (this *TcpPacket) Save(),
// so the next packet will make copy the payload into it's own new heap allocation.
// Else the buffer will be overwritten by the next packet.
func NewPacket2(pkthdr_ptr unsafe.Pointer, buf_ptr unsafe.Pointer, datalinkType int32) *TcpPacket {
	var packet TcpPacket
	if NewPacketAllocless(pkthdr_ptr, buf_ptr, datalinkType, &packet) {
		return &packet
	}
	return nil
}

// alloc-less version of NewPacket2.  Ret false if error.
func NewPacketAllocless(pkthdr_ptr unsafe.Pointer, buf_ptr unsafe.Pointer, datalinkType int32, packet *TcpPacket) bool {
	pkthdr := *(*C.struct_pcap_pkthdr)(pkthdr_ptr)

	if pkthdr.caplen != pkthdr.len {
		return false // Errorf("incomplete packet")
	}

	packet.Timestamp = time.Unix(int64(pkthdr.ts.tv_sec), int64(pkthdr.ts.tv_usec)*1000)

	var ipv6 bool

	if datalinkType == C.DLT_LINUX_SLL {
		// unwrap cooked packet
		ipv6 = (*C.struct_gen_sll)(buf_ptr).protocol == LINUX_SLL_IPV6
		buf_ptr = unsafe.Pointer(uintptr(buf_ptr) + uintptr(C.SLL_HDR_LEN))
	} else if datalinkType == C.DLT_EN10MB {
		// unwrap ethernet packet
		switch (*C.struct_ether_header)(buf_ptr).ether_type {
		case 0: // The "cooked" headers have an extra two bytes.
			buf_ptr = unsafe.Pointer(uintptr(buf_ptr) + uintptr(C.ETHER_HDR_LEN) + uintptr(2))
		case ETHERTYPE_IP:
			buf_ptr = unsafe.Pointer(uintptr(buf_ptr) + uintptr(C.ETHER_HDR_LEN))
		case ETHERTYPE_IPV6:
			ipv6 = true
			buf_ptr = unsafe.Pointer(uintptr(buf_ptr) + uintptr(C.ETHER_HDR_LEN))
		default:
			return false // Errorf("unsupported packet type=%d", ethhdr.ether_type)
		}
	} else {
		return false // Errorf("unsupported packet format %d", datalinkType)
	}

	var dataoffset, paylen, flags uint16

	if ipv6 {
		// unwrap IPv6 packet
		var iphdr = (*C.struct_gen_ip6hdr)(buf_ptr)
		// verify version and protocol
		if iphdr.misc&0xF0 != 6<<4 || iphdr.next_hdr != C.IPPROTO_TCP {
			return false
		}

		// leave address re-ordering/whatever to consumer
		packet.SrcAddr0 = uint32(iphdr.src_addr0)
		packet.SrcAddr1 = uint32(iphdr.src_addr1)
		packet.SrcAddr2 = uint32(iphdr.src_addr2)
		packet.SrcAddr3 = uint32(iphdr.src_addr3)
		packet.DstAddr0 = uint32(iphdr.dst_addr0)
		packet.DstAddr1 = uint32(iphdr.dst_addr1)
		packet.DstAddr2 = uint32(iphdr.dst_addr2)
		packet.DstAddr3 = uint32(iphdr.dst_addr3)

		// unwrap tcp packet
		buf_ptr = unsafe.Pointer(uintptr(buf_ptr) + IPV6_HEADER_LEN)
		var tcphdr = (*C.struct_gen_tcphdr)(buf_ptr)

		packet.AckSeq = uint32(tcphdr.ack_seq)
		packet.Seq = uint32(tcphdr.seq)
		packet.Source = uint16(tcphdr.source)
		packet.Dest = uint16(tcphdr.dest)

		flags = uint16(tcphdr.flags)
		dataoffset = uint16(flags>>2) & 0x3C

		paylen = uint16(iphdr.len<<8) | uint16(iphdr.len>>8) - dataoffset
	} else {
		// unwrap ip packet
		var iphdr = (*C.struct_gen_iphdr)(buf_ptr)
		// verify protocol
		if iphdr.protocol != C.IPPROTO_TCP {
			return false // Errorf("unsupported packet proto=%d", iphdr.protocol)
		}

		packet.DstAddr0 = uint32(iphdr.dst_addr)
		packet.SrcAddr0 = uint32(iphdr.src_addr)

		// unwrap tcp packet
		iphdrlen := uint16(iphdr.misc&0x0F) * 4
		buf_ptr = unsafe.Pointer(uintptr(buf_ptr) + uintptr(iphdrlen))
		var tcphdr = (*C.struct_gen_tcphdr)(buf_ptr)

		packet.AckSeq = uint32(tcphdr.ack_seq)
		packet.Seq = uint32(tcphdr.seq)
		packet.Source = uint16(tcphdr.source)
		packet.Dest = uint16(tcphdr.dest)

		flags = uint16(tcphdr.flags)
		dataoffset = uint16(flags>>2) & 0x3C

		paylen = uint16(iphdr.len<<8) | uint16(iphdr.len>>8) - iphdrlen - dataoffset
	}

	*((*reflect.SliceHeader)(unsafe.Pointer(&packet.Payload))) = reflect.SliceHeader{Data: uintptr(unsafe.Pointer(uintptr(buf_ptr) + uintptr(dataoffset))), Len: int(paylen), Cap: int(paylen)}

	packet.Flags = (flags>>8 | flags<<8) & uint16(0x01FF)
	packet.Dest = packet.Dest>>8 | packet.Dest<<8
	packet.Source = packet.Source>>8 | packet.Source<<8
	packet.Seq = packet.Seq>>24 | packet.Seq&uint32(0x00ff0000)>>8 | packet.Seq&uint32(0x0000ff00)<<8 | packet.Seq<<24
	packet.AckSeq = packet.AckSeq>>24 | packet.AckSeq&uint32(0x00ff0000)>>8 | packet.AckSeq&uint32(0x0000ff00)<<8 | packet.AckSeq<<24

	return true
}
