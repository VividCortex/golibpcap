// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build safe appengine

package pkt

import (
	"net"
)

type EthHdr struct {
	SrcAddr   net.HardwareAddr // the sender's MAC address
	DstAddr   net.HardwareAddr // the receiver's MAC address
	EtherType uint16           // packet type ID field
}
