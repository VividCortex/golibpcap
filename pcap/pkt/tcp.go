// Copyright 2012 The golibpcap Authors. All rights reserved.                      
// Use of this source code is governed by a BSD-style                              
// license that can be found in the LICENSE file.

package pkt

import (
	"fmt"
)

// TCP flags: use these constants bitwise with the TcpHdr.Flags field to detect
// the presence of a particular TCP flag.
const (
	TCP_NULL = uint16(0x0000) // No flags set
	TCP_FIN  = uint16(0x0001) // No more data from sender
	TCP_SYN  = uint16(0x0002) // Synchronize sequence numbers
	TCP_RST  = uint16(0x0004) // Reset the connection
	TCP_PSH  = uint16(0x0008) // Push the buffered data
	TCP_ACK  = uint16(0x0010) // Acknowledgment field is significant
	TCP_URG  = uint16(0x0020) // Urgent pointer field is significant
	TCP_ECE  = uint16(0x0040) // ECN-Echo
	TCP_CWR  = uint16(0x0080) // Congestion Window Reduced
	TCP_NS   = uint16(0x0100) // ECN-nonce concealment protection
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
