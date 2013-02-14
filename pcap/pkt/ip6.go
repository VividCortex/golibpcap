// Copyright 2012 The golibpcap Authors. All rights reserved.                      
// Use of this source code is governed by a BSD-style                              
// license that can be found in the LICENSE file.                                  

package pkt

import (
	"fmt"
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
