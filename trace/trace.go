// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// WARNING: This package is experimental and may change without notice!
//
// The trace package provides support for analyzing and storing the data
// gathered by the pcap package.
//
package trace

import (
	"compress/gzip"
	"encoding/gob"
	"errors"
	"io"
	"time"

	"github.com/VividCortex/golibpcap/pcap/pkt"
	"github.com/VividCortex/golibpcap/pcap/stat"
)

const (
	Version     = "beta-0-0-1"       // For compatibility checks if PktTrace changes
	ArchiveType = "application/gzip" // MIME type for archived PktTrace results
)

// Package errors
var (
	ErrApplicationLayerHeader = errors.New("Application Layer Header Error")
	ErrBadPort                = errors.New("No ports match")
	ErrEmptyData              = errors.New("Data is empty")
	ErrFlowMismatch           = errors.New("Flows do not match")
	ErrNetworkLayerHeader     = errors.New("Network Layer Header Error")
	ErrSameSrcDstPorts        = errors.New("Src and Dst ports match")
	ErrTCPSeqMissing          = errors.New("TCP Sequnce Number Missing")
	ErrTransportLayerHeader   = errors.New("Transport Layer Header Error")
)

var (
	ApplicationLayer = 3       // Index for OSI Application Layer in Pkt.Headers
	ServerSrcPort    = int(80) // Expected server source port
)

func init() {
	gob.Register(&pkt.EthHdr{})
	gob.Register(&pkt.HttpHdr{})
	gob.Register(&pkt.Ip6Hdr{})
	gob.Register(&pkt.IpHdr{})
	gob.Register(&pkt.Packet{})
	gob.Register(&pkt.TcpHdr{})
	gob.Register(&pkt.UdpHdr{})
}

// A PktTrace combines the pkt.Packet data with meta data so that it can be
// archived and analyzed.
type PktTrace struct {
	Version    string         // For trace version compatibility issues
	LibVersion string         // The version of libpcap being used
	Date       time.Time      // Date the trace was created
	Notes      string         // Meta data not otherwise specified
	MetaPcap   *MetaPcap      // Meta data from pcap.Pcap
	Stats      *stat.Stat     // Capture stats straight from libpcap
	Data       *[]*pkt.Packet // The headers of the captured packets
}

// A MetaPcap is a copy of the meta data from pcap.Pcap.  We keep this copy
// separate so that it cannot be executed by mistake, and by not depending on
// the system's C libraries it can be more portable.
type MetaPcap struct {
	Device   string   // The device used for packet capture
	FileName string   // The filename used for reading a pcap savefile
	Snaplen  int32    // Specifies the maximum number of bytes to capture
	Promisc  int32    // 0->false, 1->true
	Timeout  int32    // ms
	Filters  []string // track filters applied to the capture
}

// PktTraceFromArchive reads a given gzip compressed gob encoded PktTrace.  This
// is the standard format for storing a PktTrace to a file.
func PktTraceFromArchive(r io.Reader) (*PktTrace, error) {
	t := &PktTrace{}
	gz, err := gzip.NewReader(r)
	if err != nil {
		return t, err
	}
	defer gz.Close()
	gd := gob.NewDecoder(gz)
	err = gd.Decode(t)
	return t, err
}

// Archive saves a PktTrace to a gzip compressed gob encoded file.
func (t *PktTrace) Archive(w io.Writer) error {
	gz, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
	if err != nil {
		return err
	}
	defer gz.Close()
	ge := gob.NewEncoder(gz)
	return ge.Encode(t)
}
