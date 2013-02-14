// Copyright 2013 The golibpcap Authors. All rights reserved.                      
// Use of this source code is governed by a BSD-style                              
// license that can be found in the LICENSE file.

// +build safe appengine

package pkt

type TcpHdr struct {
	Source uint16 // source port
	Dest   uint16 // destination port
	Seq    uint32 // sequence number
	AckSeq uint32 // acknowledgement number
	Doff   uint8  // The length of the TCP header (data offset) in 32 bit words.
	Flags  uint16 // TCP flags per RFC 793, September, 1981
	Window uint16 // window advertisement
	Check  uint16 // checksum
	UrgPtr uint16 // urgent pointer
}
