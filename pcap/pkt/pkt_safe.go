// Copyright 2013 The golibpcap Authors. All rights reserved.                      
// Use of this source code is governed by a BSD-style                              
// license that can be found in the LICENSE file.

// +build safe appengine

package pkt

import (
	"time"
)

type Packet struct {
	Time    time.Time // time stamp from the nic
	Caplen  uint32    // length of portion present
	Len     uint32    // length this packet (off wire)
	Headers []Hdr     // Go wrappers for C pkt headers
}
