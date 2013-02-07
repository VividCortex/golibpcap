// Copyright 2013 The golibpcap Authors. All rights reserved.                        
// Use of this source code is governed by a BSD-style                              
// license that can be found in the LICENSE file.

// The stat package provides support for collecting libpcap stats.
//
package stat

import (
	"fmt"
)

// Stat is the wrapper for the pcap_stat struct in <pcap.h>.
type Stat struct {
	Captured  uint32 // The number of packets captured.
	Received  uint32 // The number of packets received (pre-filter).
	Dropped   uint32 // The number of packets dropped.
	IfDropped uint32 // The number of drops by the interface.
}

// JsonElement returns and JSON encoded form of the Stat struct.
func (s *Stat) JsonString() string {
	return fmt.Sprintf("\"stat\":{\"captured\":%d,\"received\":%d,\"dropped\":%d,\"ifDropped\":%d}",
		s.Captured,
		s.Received,
		s.Dropped,
		s.IfDropped)
}

// Provides a human readable output for the Stat struct.
func (s *Stat) String() string {
	return fmt.Sprintf("Captured: %d\nReceived: %d\nDropped: %d\nIfDropped: %d",
		s.Captured,
		s.Received,
		s.Dropped,
		s.IfDropped)
}
