// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !safe,!appengine

package pkt

/*
#cgo LDFLAGS: /tmp/usr/lib/libpcap.a
#include "../pcap.h"
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
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

	var pl []byte // the transport layer payload
	switch p.Headers[NetworkLayer].(InetProtoHdr).Proto() {
	case C.IPPROTO_TCP:
		p.Headers[TransportLayer], _ = NewTcpHdr(buf)
		pl = p.Headers[TransportLayer].(*TcpHdr).GetPayloadBytes(
			p.Headers[NetworkLayer].(InetProtoHdr).PL())
	case C.IPPROTO_UDP:
		p.Headers[TransportLayer], _ = NewUdpHdr(buf)
		return
	case C.IPPROTO_ICMP:
		//TODO(gavaletz) ICMP
		return
	default:
		return
	}

	// Looks to see if a packet represents the beginning of an  HTTP request
	// or a HTTP response from the server.  This goes beyond the normal pcap
	// library operations.
	if len(pl) > 14 {
		httpHdr := NewHttpHdr(pl)
		if httpHdr != nil {
			p.Headers = append(p.Headers, httpHdr)
		}
	}
	//TODO(gavaletz) SDPY
}
