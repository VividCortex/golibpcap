// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trace

import (
	"fmt"
	"net"

	"code.google.com/p/golibpcap/pcap/pkt"
)

// An IPTuple encapsulates the source and destination address for analysing IP
// packet traces.
type IPTuple struct {
	Src net.IP // The source IP address
	Dst net.IP // The destination IP address
}

// NewIPTuple constructs an IPTuple from the information in the pkt.Packet
// headers.  This assumes that the packet is an IP packet.
func NewIPTuple(p *pkt.Packet) (*IPTuple, error) {
	ip := &IPTuple{}
	if p == nil {
		return ip, nil
	}
	ipHdr, ok := p.Headers[pkt.NetworkLayer].(pkt.InetProtoHdr)
	if !ok || ipHdr == nil {
		return ip, ErrNetworkLayerHeader
	}
	ip.Src = ipHdr.Src()
	ip.Dst = ipHdr.Dst()
	return ip, nil
}

// String returns a serialized form of an IPTuple suitable for use as a key.
func (t *IPTuple) String() string {
	return fmt.Sprintf("%s->%s", t.Src, t.Dst)
}

// Equal returns true if t and x have the same source and destination IP
// address.
func (t *IPTuple) Equal(x *IPTuple) bool {
	if t.Src.Equal(x.Src) {
		return t.Dst.Equal(x.Dst)
	}
	return false
}
