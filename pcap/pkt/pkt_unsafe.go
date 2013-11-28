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
	var dcopy = make([]byte, len(this.Payload))
	copy(dcopy, this.Payload)
	this.Payload = dcopy
	this.saved = true
}

// NewPacket2 takes a libpcap buffer and extracts only TCP/IPv4 packets into
// packet (declared just above) without creating any new data in the heap. If
// the recipient of this packet needs to keep a copy of it, it should call
// func (this *TcpPacket) Save(), so the next packet will be created in a new
// heap allocation.
func NewPacket2(pkthdr_ptr unsafe.Pointer, buf_ptr unsafe.Pointer) (TcpPacket, error) {
	var packet TcpPacket

	pkthdr := *(*C.struct_pcap_pkthdr)(pkthdr_ptr)

	// unwrap ethernet packet
	var ethhdr = (*C.struct_ether_header)(buf_ptr)
	var ethtype = uint16(ethhdr.ether_type)
	// we are assuming little endian arch
	ethtype = (ethtype>>8 | ethtype&uint16(0x00ff)<<8)

	if ethtype == 0 {
		// The "cooked" headers have an extra two bytes.
		buf_ptr = unsafe.Pointer(uintptr(buf_ptr) + uintptr(C.ETHER_HDR_LEN) + uintptr(2))
	} else {
		buf_ptr = unsafe.Pointer(uintptr(buf_ptr) + uintptr(C.ETHER_HDR_LEN))
	}

	if ethtype != C.ETHERTYPE_IP && ethtype != 0 {
		return packet, fmt.Errorf("unsupported packet")
	}

	// unwrap ip packet
	var iphdr = (*C.struct_iphdr)(buf_ptr)
	var iphdrlen = *(*byte)(buf_ptr) & 0x0F

	var paylen = uint16(iphdr.tot_len)
	// we are assuming little endian arch
	paylen = (paylen>>8 | paylen&uint16(0x00ff)<<8) - uint16(iphdrlen*4)

	buf_ptr = unsafe.Pointer(uintptr(buf_ptr) + uintptr(iphdrlen*4))

	if uint8(iphdr.protocol) != C.IPPROTO_TCP {
		return packet, fmt.Errorf("unsupported packet")
	}

	// unwrap tcp packet
	var tcphdr = (*C.struct_tcphdr)(buf_ptr)
	var dataoffset = *(*byte)(unsafe.Pointer(uintptr(buf_ptr) + uintptr(12))) >> 4

	packet.DstAddr = uint32(iphdr.daddr)
	packet.SrcAddr = uint32(iphdr.saddr)
	packet.AckSeq = uint32(tcphdr.ack_seq)
	packet.Seq = uint32(tcphdr.seq)
	packet.Source = uint16(tcphdr.source)
	packet.Dest = uint16(tcphdr.dest)
	packet.Flags = *(*uint16)(unsafe.Pointer(uintptr(buf_ptr) + uintptr(12)))
	packet.Timestamp = time.Unix(int64(pkthdr.ts.tv_sec), int64(pkthdr.ts.tv_usec)*1000)
	packet.IsRequest = false

	sh := (*reflect.SliceHeader)((unsafe.Pointer(&packet.Payload)))
	sh.Cap = int(paylen - uint16(dataoffset*4))
	sh.Len = sh.Cap
	sh.Data = uintptr(unsafe.Pointer(uintptr(buf_ptr) + uintptr(dataoffset*4)))

	// Network to hosts. Right now we are assuming little endian cpu.
	packet.Flags = (packet.Flags>>8 | packet.Flags&uint16(0x00ff)<<8) & uint16(0x01FF)
	packet.Dest = packet.Dest>>8 | packet.Dest&uint16(0x00ff)<<8
	packet.Source = packet.Source>>8 | packet.Source&uint16(0x00ff)<<8
	packet.Seq = packet.Seq>>24 | packet.Seq&uint32(0x00ff0000)>>8 | packet.Seq&uint32(0x0000ff00)<<8 | packet.Seq<<24
	packet.AckSeq = packet.AckSeq>>24 | packet.AckSeq&uint32(0x00ff0000)>>8 | packet.AckSeq&uint32(0x0000ff00)<<8 | packet.AckSeq<<24
	return packet, nil
}
