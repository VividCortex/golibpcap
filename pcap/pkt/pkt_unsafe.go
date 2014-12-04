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
	DstAddr   uint32
	SrcAddr   uint32
	AckSeq    uint32
	Seq       uint32
	Source    uint16
	Dest      uint16
	Flags     uint16
	Payload   []byte
	Timestamp time.Time
	IsRequest bool
	saved     bool
}

func (this *TcpPacket) Save() {
	if !this.saved {
		var dcopy = make([]byte, len(this.Payload))
		copy(dcopy, this.Payload)
		this.Payload = dcopy
		this.saved = true
	}
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
			plA += "#"
		}
		sbuf[0] = c
		plH += hex.EncodeToString(sbuf[:])
	}
	return "[" + plA + "] [" + plH + "]"
}

// FIXME: we are assuming little endian arch
const ETHERTYPE_IP = C.ETHERTYPE_IP>>8 | C.ETHERTYPE_IP&0xFF<<8

// NewPacket2 takes a libpcap buffer and extracts only TCP/IPv4 packets into
// a TcpPacket without creating any new data in the heap. If the recipient of
// this packet needs to keep a copy of it, it should call func (this *TcpPacket) Save(),
// so the next packet will make copy the payload into it's own new heap allocation.
// Else the buffer will be overwritten by the next packet.
func NewPacket2(pkthdr_ptr unsafe.Pointer, buf_ptr unsafe.Pointer, datalinkType int32) (*TcpPacket, error) {
	var packet TcpPacket

	pkthdr := *(*C.struct_pcap_pkthdr)(pkthdr_ptr)

	if pkthdr.caplen != pkthdr.len {
		return nil, fmt.Errorf("incomplete packet")
	}

	if datalinkType == C.DLT_LINUX_SLL {
		// unwrap cooked packet
		buf_ptr = unsafe.Pointer(uintptr(buf_ptr) + uintptr(C.SLL_HDR_LEN))
	} else if datalinkType == C.DLT_EN10MB {
		// unwrap ethernet packet
		var ethhdr = (*C.struct_ether_header)(buf_ptr)

		switch ethhdr.ether_type {
		case 0: // The "cooked" headers have an extra two bytes.
			buf_ptr = unsafe.Pointer(uintptr(buf_ptr) + uintptr(C.ETHER_HDR_LEN) + uintptr(2))
		case ETHERTYPE_IP:
			buf_ptr = unsafe.Pointer(uintptr(buf_ptr) + uintptr(C.ETHER_HDR_LEN))
		default:
			return nil, fmt.Errorf("unsupported packet type=%d", ethhdr.ether_type)
		}
	} else {
		//log.Println("Unsupported packet format", datalinkType, "pkt", dumpBuf(buf_ptr, 32))
		return nil, fmt.Errorf("unsupported packet format %d", datalinkType)
	}

	// unwrap ip packet
	iphdr := getIphdr(buf_ptr)

	if getProtocol(iphdr) != C.IPPROTO_TCP {
		return nil, fmt.Errorf("unsupported packet proto=%d", getProtocol(iphdr))
	}

	var iphdrlen = uint16((*(*byte)(buf_ptr) & 0x0F) * 4)

	buf_ptr = unsafe.Pointer(uintptr(buf_ptr) + uintptr(iphdrlen))

	// unwrap tcp packet
	var tcphdr = (*C.struct_gen_tcphdr)(buf_ptr)

	packet.DstAddr = uint32(iphdr.daddr)
	packet.SrcAddr = uint32(iphdr.saddr)
	packet.AckSeq = uint32(tcphdr.ack_seq)
	packet.Seq = uint32(tcphdr.seq)
	packet.Source = uint16(tcphdr.source)
	packet.Dest = uint16(tcphdr.dest)
	packet.Timestamp = time.Unix(int64(pkthdr.ts.tv_sec), int64(pkthdr.ts.tv_usec)*1000)

	var flags = uint16(tcphdr.flags)
	var dataoffset = (flags >> 2) & 0x3C

	paylen := getPaylen(iphdr)
	paylen = (paylen>>8 | paylen<<8) - iphdrlen - dataoffset // FIXME: we are assuming little endian arch

	sh := (*reflect.SliceHeader)((unsafe.Pointer(&packet.Payload)))
	sh.Cap = int(paylen)
	sh.Len = int(paylen)
	sh.Data = uintptr(unsafe.Pointer(uintptr(buf_ptr) + uintptr(dataoffset)))

	// FIXME: Refactor to create a generalized ntohs/ntohl set of functions.
	// Network to hosts. Right now we are assuming little endian cpu.
	packet.Flags = (flags>>8 | flags<<8) & uint16(0x01FF)
	packet.Dest = packet.Dest>>8 | packet.Dest<<8
	packet.Source = packet.Source>>8 | packet.Source<<8
	packet.Seq = packet.Seq>>24 | packet.Seq&uint32(0x00ff0000)>>8 | packet.Seq&uint32(0x0000ff00)<<8 | packet.Seq<<24
	packet.AckSeq = packet.AckSeq>>24 | packet.AckSeq&uint32(0x00ff0000)>>8 | packet.AckSeq&uint32(0x0000ff00)<<8 | packet.AckSeq<<24
	return &packet, nil
}
