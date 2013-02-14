// Copyright 2013 The golibpcap Authors. All rights reserved.                      
// Use of this source code is governed by a BSD-style                              
// license that can be found in the LICENSE file.

// +build safe appengine

package pkt

type UdpHdr struct {
	Source uint16 // source port
	Dest   uint16 // destination port
	Len    uint16 // datagram length (header + payload) in bytes
	Check  uint16 // checksum
}
