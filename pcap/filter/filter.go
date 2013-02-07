// Copyright 2013 The golibpcap Authors. All rights reserved.                        
// Use of this source code is governed by a BSD-style                              
// license that can be found in the LICENSE file.

// The filter package provides support for assembling fell formed bpf filters.
//
package filter

import (
	"fmt"
	"net"
)

// Represents the elements that go into a very common bpf filter.
//
// Most users can give the same filter strings that they would give to tcpdump
// directly to the Setfilter function.
type Filter struct {
	SrcIP   net.IP // The source IP address
	SrcPort int    // The source port number
	DstIp   net.IP // The destination IP address
	DstPort int    // The destination port number
}

// Given a complete Filter it generates the string form for Setfilter.
func (f *Filter) String() string {
	return fmt.Sprintf("ip src %s and src port %d and dst %s and dst port %d",
		f.SrcIP.String(),
		f.SrcPort,
		f.DstIp.String(),
		f.DstPort)
}
