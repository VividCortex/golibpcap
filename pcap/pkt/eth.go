// Copyright 2012 The golibpcap Authors. All rights reserved.                      
// Use of this source code is governed by a BSD-style                              
// license that can be found in the LICENSE file.

package pkt

import (
	"fmt"
)

// JsonElement returns a JSON encoding of the EthHdr struct.
func (h *EthHdr) JsonElement() string {
	return fmt.Sprintf("\"ether_header\":{\"ether_shost\":\"%s\",\"ether_dhost\":\"%s\",\"ether_type\":%d}",
		h.SrcAddr.String(),
		h.DstAddr.String(),
		h.EtherType)
}

// CsvElement returns a CSV encoding of the EthHdr struct.
// The string "ETH" signifies the beginning of the EthHdr.
func (h *EthHdr) CsvElement() string {
	return fmt.Sprintf("\"ETH\",\"%s\",\"%s\",%d",
		h.SrcAddr.String(),
		h.DstAddr.String(),
		h.EtherType)
}

// String returns a minimal encoding of the EthHdr struct.
func (h *EthHdr) String() string {
	return fmt.Sprintf("%s->%s %#x",
		h.SrcAddr.String(),
		h.DstAddr.String(),
		h.EtherType)
}
