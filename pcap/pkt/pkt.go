// Copyright 2012 The golibpcap Authors. All rights reserved.                      
// Use of this source code is governed by a BSD-style                              
// license that can be found in the LICENSE file.

// The pkt package provides access to the packet internals.                        
//
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
	"fmt"
	"strings"
	"time"
	"unsafe"
)

// The Packet struct is a wrapper for the pcap_pkthdr struct in <pcap.h>.
type Packet struct {
	PcapHdr *C.struct_pcap_pkthdr // see <pcap.h> struct pcap_pkthdr
	Time    time.Time             // time stamp from the nic
	Caplen  uint32                // length of portion present
	Len     uint32                // length this packet (off wire)
	Headers []Hdr                 // Go wrappers for C pkt headers
	Buf     unsafe.Pointer        // packet data (*C.u_char)
}

// The Hdr interface allows us to deal with an array of headers.
type Hdr interface {
	JsonElement() string
	String() string
}

// Decode decodes the headers of a Packet.
func (p *Packet) Decode() {

	ethHdr, buf := NewEthHdr(p.Buf)
	p.Headers = append(p.Headers, ethHdr)

	var (
		proto         uint8  // the transport layer protocol
		payloadLength uint16 // the length (bytes) of the IP payload
		pl            []byte // the transport layer payload
	)

	switch ethHdr.EtherType {
	case C.ETHERTYPE_IP:
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
		//TODO(gavaletz) UDP
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

// JsonString  returns a JSON encoding of the Packet struct.
func (p *Packet) JsonString() string {
	s := make([]string, len(p.Headers))
	for i := range p.Headers {
		s[i] = p.Headers[i].JsonElement()
	}
	return fmt.Sprintf("{\"time\":%d,%s}", p.Time.UnixNano(), strings.Join(s, ","))
}

// String returns a minimal encoding of the Packet struct.
func (p *Packet) String() string {
	s := make([]string, len(p.Headers))
	for i := range p.Headers {
		s[i] = p.Headers[i].String()
	}
	return fmt.Sprintf("%s %s", p.Time, strings.Join(s, " "))
}
