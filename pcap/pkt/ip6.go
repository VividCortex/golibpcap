// Copyright 2012 The golibpcap Authors. All rights reserved.                      
// Use of this source code is governed by a BSD-style                              
// license that can be found in the LICENSE file.                                  

package pkt

import (
	"fmt"
	"net"
)

// JsonElement returns a JSON encoding of the Ip6Hdr struct.
func (h *Ip6Hdr) JsonElement() string {
	return fmt.Sprintf("\"ip6hdr\":{\"ip6_src\":\"%s\",\"ip6_dst\":\"%s\",\"next_header\":%d}",
		h.SrcAddr.String(),
		h.DstAddr.String(),
		h.NextHeader)
}

// CsvElement returns a CSV encoding of the Ip6Hdr struct.
// The string "IP6" signifies the beginning of the Ip6Hdr.
func (h *Ip6Hdr) CsvElement() string {
	return fmt.Sprintf("\"IP6\",\"%s\",\"%s\",%d",
		h.SrcAddr.String(),
		h.DstAddr.String(),
		h.NextHeader)
}

// String returns a minimal encoding of the Ip6Hdr struct.
func (h *Ip6Hdr) String() string {
	return fmt.Sprintf("%s->%s %#x",
		h.SrcAddr.String(),
		h.DstAddr.String(),
		h.NextHeader)
}

// Src returns the network layer source address.
func (h *Ip6Hdr) Src() net.IP {
	return h.SrcAddr
}

// Dst returns the network layer destination address.
func (h *Ip6Hdr) Dst() net.IP {
	return h.DstAddr
}

// Proto returns the IP protocol number.
func (h *Ip6Hdr) Proto() uint8 {
	return h.NextHeader
}

// PL returns the Payload length.
func (h *Ip6Hdr) PL() uint16 {
	return h.PayloadLen
}
