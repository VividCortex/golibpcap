// Copyright 2013 The golibpcap Authors. All rights reserved.                        
// Use of this source code is governed by a BSD-style                              
// license that can be found in the LICENSE file.

// The trace package provides support for analyzing and storing the data
// gathered by the pcap package.
//
package trace

import (
	"time"

	"code.google.com/p/golibpcap/pcap/pkt"
	"code.google.com/p/golibpcap/pcap/stat"
)

const (
	Version = "beta-0-0-0"
)

// A PktTrace combines the pkt.Packet data with meta data so that it can be
// archived and analyzed.
type PktTrace struct {
	Version  string         // For trace version compatibility issues
	Date     time.Time      // Date the trace was created
	Notes    string         // Meta data not otherwise specified
	MetaPcap *MetaPcap      // Meta data from pcap.Pcap
	Stats    *stat.Stat     // Capture stats straight from libpcap
	Data     *[]*pkt.Packet // The headers of the captured packets
}

// A MetaPcap is a copy of the meta data from pcap.Pcap.  We keep this copy
// separate so that it cannot be executed by mistake, and by not depending on
// the system's C libraries it can be more portable.
type MetaPcap struct {
	Device  string   // The device used for packet capture
	Snaplen int32    // Specifies the maximum number of bytes to capture
	Promisc int32    // 0->false, 1->true
	Timeout int32    // ms
	Filters []string // track filters applied to the capture
}
