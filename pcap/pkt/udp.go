// Copyright 2012 The golibpcap Authors. All rights reserved.                      
// Use of this source code is governed by a BSD-style                              
// license that can be found in the LICENSE file.

package pkt

import (
	"fmt"
)

// JsonElement returns a JSON encoding of the UdpHdr struct.
func (h *UdpHdr) JsonElement() string {
	return fmt.Sprintf("\"udphdr\":{\"source\":%d,\"dest\":%d,\"len\":%d,\"check\":%d}",
		h.Source,
		h.Dest,
		h.Len,
		h.Check)
}

// CsvElement returns a CSV encoding of the UdpHdr struct.
// The string "UDP" signifies the beginning of the UdpHdr.
func (h *UdpHdr) CsvElement() string {
	return fmt.Sprintf("\"UDP\",%d,%d,%d,%d,%d",
		h.Source,
		h.Dest,
		h.Len,
		h.Check)
}

// String returns a minimal encoding of the UdpHdr struct.
func (h *UdpHdr) String() string {
	return fmt.Sprintf("%d->%d %d %d",
		h.Source,
		h.Dest,
		h.Len,
		h.Check)
}
