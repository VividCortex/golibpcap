// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trace

import (
	"fmt"
	"net"

	"code.google.com/p/golibpcap/pcap/pkt"
)

// A TCPTuple encapsulates the source and destination address for analysing
// TCP/IP packet traces.
type TCPTuple struct {
	Src *net.TCPAddr // The source IP address
	Dst *net.TCPAddr // The destination IP address
}

// NewTCPTuple constructs a TCPTuple from the information in the pkt.Packet
// headers.  This assumes that the packet is a TCP/IP packet.
func NewTCPTuple(p *pkt.Packet) (*TCPTuple, error) {
	t := &TCPTuple{
		Src: &net.TCPAddr{},
		Dst: &net.TCPAddr{},
	}
	if p == nil {
		return t, nil
	}
	ipHdr, ok := p.Headers[pkt.NetworkLayer].(pkt.InetProtoHdr)
	if !ok || ipHdr == nil {
		return t, ErrNetworkLayerHeader
	}
	t.Src.IP = ipHdr.Src()
	t.Dst.IP = ipHdr.Dst()
	tcpHdr, ok := p.Headers[pkt.TransportLayer].(*pkt.TcpHdr)
	if !ok || tcpHdr == nil {
		return t, ErrTransportLayerHeader
	}
	t.Src.Port = int(tcpHdr.Source)
	t.Dst.Port = int(tcpHdr.Dest)
	return t, nil
}

// srcByPort sets the address with the given port number as the source address
// in the TCPTuple.  If neither address has the given port or if both do it is
// considered an error and nothing is changed.
func (t *TCPTuple) srcByPort(p int) error {
	if t.Src.Port != p {
		if t.Dst.Port != p {
			return ErrBadPort
		}
		tmp := t.Src
		t.Src = t.Dst
		t.Dst = tmp
	}
	if t.Dst.Port == p {
		return ErrSameSrcDstPorts
	}
	return nil
}

// String returns a serialized form of a TCPTuple suitable for use as a key.
func (t *TCPTuple) String() string {
	return fmt.Sprintf("%s<->%s", t.Src, t.Dst)
}

// Equal returns true if t and x have the same source and destination IP:Port
// address.
func (t *TCPTuple) Equal(x *TCPTuple) bool {
	if x == nil {
		return false
	}
	if t.Src.Port == x.Src.Port {
		if t.Dst.Port == x.Dst.Port {
			if t.Src.IP.Equal(x.Src.IP) {
				return t.Dst.IP.Equal(x.Dst.IP)
			}
		}
	}
	return false
}

// REqual returns true if both source addresses match both destination addresses.
func (t *TCPTuple) REqual(x *TCPTuple) bool {
	if x == nil {
		return false
	}
	if t.Src.Port == x.Dst.Port {
		if t.Dst.Port == x.Src.Port {
			if t.Src.IP.Equal(x.Dst.IP) {
				return t.Dst.IP.Equal(x.Src.IP)
			}
		}
	}
	return false
}

// MatchFlow returns t.Equal || t.REqual
func (t *TCPTuple) MatchFlow(x *TCPTuple) bool {
	return t.Equal(x) || t.REqual(x)
}
