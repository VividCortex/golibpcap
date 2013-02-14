// Copyright 2012 The golibpcap Authors. All rights reserved.                      
// Use of this source code is governed by a BSD-style                              
// license that can be found in the LICENSE file.

package pkt

import (
	"fmt"
)

// JsonElement returns a JSON encoding of the TcpHdr struct.
func (h *TcpHdr) JsonElement() string {
	return fmt.Sprintf("\"tcphdr\":{\"source\":%d,\"dest\":%d,\"seq\":%d,\"ack_seq\":%d,\"flags\":%d}",
		h.Source,
		h.Dest,
		h.Seq,
		h.AckSeq,
		h.Flags)
}

// CsvElement returns a CSV encoding of the TcpHdr struct.
// The string "TCP" signifies the beginning of the TcpHdr.
func (h *TcpHdr) CsvElement() string {
	return fmt.Sprintf("\"TCP\",%d,%d,%d,%d,%d",
		h.Source,
		h.Dest,
		h.Seq,
		h.AckSeq,
		h.Flags)
}

// String returns a minimal encoding of the TcpHdr struct.
func (h *TcpHdr) String() string {
	return fmt.Sprintf("%d->%d %d %d %#x",
		h.Source,
		h.Dest,
		h.Seq,
		h.AckSeq,
		h.Flags)
}
