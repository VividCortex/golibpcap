// Copyright 2013 The golibpcap Authors. All rights reserved.                      
// Use of this source code is governed by a BSD-style                              
// license that can be found in the LICENSE file.

// +build !safe,!appengine

package pkt

/*
#cgo LDFLAGS: -lpcap
#include <pcap.h>
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
		Time:   time.Unix(int64(pkthdr.ts.tv_sec), int64(pkthdr.ts.tv_usec)),
		Caplen: uint32(pkthdr.caplen),
		Len:    uint32(pkthdr.len),
		buf:    buf_ptr,
	}
	p.decode()
	return p
}

// Decode decodes the headers of a Packet.
func (p *Packet) decode() {

	ethHdr, buf := NewEthHdr(p.buf)
	p.Headers = append(p.Headers, ethHdr)

	var (
		proto         uint8  // the transport layer protocol
		payloadLength uint16 // the length (bytes) of the IP payload
		pl            []byte // the transport layer payload
	)

	switch ethHdr.EtherType {
	case C.ETHERTYPE_IP, 0:
		var ipHead *IpHdr
		ipHead, buf = NewIpHdr(buf)
		proto = ipHead.Protocol
		payloadLength = ipHead.PayloadLen
		p.Headers = append(p.Headers, ipHead)
	case C.ETHERTYPE_IPV6:
		var ipHead *Ip6Hdr
		ipHead, buf = NewIp6Hdr(buf)
		proto = ipHead.NextHeader
		payloadLength = ipHead.PayloadLen
		p.Headers = append(p.Headers, ipHead)
	case C.ETHERTYPE_ARP:
		//TODO(gavaletz) ARP
		return
	default:
		return
	}

	switch proto {
	case C.IPPROTO_TCP:
		var tcpHead *TcpHdr
		tcpHead, buf = NewTcpHdr(buf)
		p.Headers = append(p.Headers, tcpHead)
		pl = tcpHead.GetPayloadBytes(payloadLength)
	case C.IPPROTO_UDP:
		var udpHead *UdpHdr
		udpHead, buf = NewUdpHdr(buf)
		p.Headers = append(p.Headers, udpHead)
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
