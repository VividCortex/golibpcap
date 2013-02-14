// Copyright 2012 The golibpcap Authors. All rights reserved.                      
// Use of this source code is governed by a BSD-style                              
// license that can be found in the LICENSE file.

package pkt

import (
	"fmt"
)

// JsonElement returns a JSON encoding of the IpHdr struct.
func (h *IpHdr) JsonElement() string {
	return fmt.Sprintf("\"iphdr\":{\"saddr\":\"%s\",\"daddr\":\"%s\",\"protocol\":%d}",
		h.SrcAddr.String(),
		h.DstAddr.String(),
		h.Protocol)
}

// CsvElement returns a CSV encoding of the IpHdr struct.
// The string "IP4" signifies the beginning of the IpHdr.
func (h *IpHdr) CsvElement() string {
	return fmt.Sprintf("\"IP4\",\"%s\",\"%s\",%d",
		h.SrcAddr.String(),
		h.DstAddr.String(),
		h.Protocol)
}

// String returns a minimal encoding of the IpHdr struct.
func (h *IpHdr) String() string {
	return fmt.Sprintf("%s->%s %#x",
		h.SrcAddr.String(),
		h.DstAddr.String(),
		h.Protocol)
}
