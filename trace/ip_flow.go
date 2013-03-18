// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trace

import (
	"time"

	"code.google.com/p/golibpcap/pcap/pkt"
)

// An IPFlow makes working with IP data easier.
type IPFlow struct {
	IPTuple   *IPTuple      // The source and destination addresses
	Data      []*pkt.Packet // The array of packets
	StartTime time.Time     // Time of the first packet
	EndTime   time.Time     // Time of the last packet
	Bytes     int64         // Number of bytes from the source to the destination
	PLBytes   int64         // Number of payload bytes from the source to the destination
}

// GetIPTraffic separates all the IP traffic in the slice of pkt.Packet into
// their respective flows.  The resulting map of IPFlow are keyed by the string
// of their IPTuple.
func GetIPTraffic(d []*pkt.Packet) map[string]*IPFlow {
	m := make(map[string]*IPFlow)
	var f *IPFlow
	for i := range d {
		t, err := NewIPTuple(d[i])
		if err != nil {
			continue
		}
		f = m[t.String()]
		if f == nil {
			f = &IPFlow{
				IPTuple: t,
			}
			m[t.String()] = f
		}
		_ = f.AddPacket(d[i])
	}
	return m
}

// AddPacket updates the meta data for a IPFlow and saves a reference to the
// pkt.Packet.  This assumes the packet addresses have been checked and the IP
// flow matches (it does not check for matching addresses).
func (f *IPFlow) AddPacket(p *pkt.Packet) error {
	ip, ok := p.Headers[pkt.NetworkLayer].(pkt.InetProtoHdr)
	if !ok || ip == nil {
		return ErrNetworkLayerHeader
	}
	if p.Time.Before(f.StartTime) || f.StartTime.IsZero() {
		f.StartTime = p.Time
	}
	if p.Time.After(f.EndTime) || f.EndTime.IsZero() {
		f.EndTime = p.Time
	}
	f.Bytes += int64(p.Len)
	f.PLBytes += int64(ip.PL())
	f.Data = append(f.Data, p)
	return nil
}
