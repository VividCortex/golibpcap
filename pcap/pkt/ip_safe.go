// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build safe appengine

package pkt

import (
	"net"
)

type IpHdr struct {
	Ihl        uint8  // header length (32bit words)
	Version    uint8  // version
	SrcAddr    net.IP // source address
	DstAddr    net.IP // dest address
	Protocol   uint8  // protocol
	TotLen     uint16 // total length (bytes)
	PayloadLen uint16 // payload length (bytes)
}
