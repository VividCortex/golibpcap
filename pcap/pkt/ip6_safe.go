// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build safe appengine

package pkt

import (
	"net"
)

type Ip6Hdr struct {
	SrcAddr    net.IP // the sender's ip6 address
	DstAddr    net.IP // the receiver's ipv6 address
	NextHeader uint8  // next header
	PayloadLen uint16 // payload length
}
