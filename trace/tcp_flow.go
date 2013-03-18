// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trace

import (
	"time"

	"code.google.com/p/golibpcap/pcap/pkt"
)

// A TCPFlow makes working with TCP data easier.
type TCPFlow struct {
	TCPTuple       *TCPTuple     // The source and destination addresses
	Data           []*pkt.Packet // The array of packets
	StartTime      time.Time     // Time of the first packet
	EndTime        time.Time     // Time of the last packet
	SrcStartSeq    uint32        // The first seq number in the flow
	DstStartSeq    uint32        // The first seq number in the flow
	SrcStartAckSeq uint32        // The first ACK seq number in the flow
	DstStartAckSeq uint32        // The first ACK seq number in the flow
	SrcBytes       int64         // Number of bytes from the source to the destination
	DstBytes       int64         // Number of bytes from the destination the source
	SrcPLBytes     int64         // Number of payload bytes from the source to the destination
	DstPLBytes     int64         // Number of payload bytes from the destination the source
	SrcPktCnt      int64         // Number of packets from the source to the destination
	DstPktCnt      int64         // Number of packets from the destination the source
}

// GetTCPTraffic separates all the TCP traffic in the slice of pkt.Packet into
// their respective flows.  The resulting map of TCPFlow are keyed by the string
// of their TCPTuple.
func GetTCPTraffic(d []*pkt.Packet) map[string]*TCPFlow {
	m := make(map[string]*TCPFlow)
	var f *TCPFlow
	for i := range d {
		t, err := NewTCPTuple(d[i])
		if err != nil {
			continue
		}
		err = t.srcByPort(ServerSrcPort)
		if err != nil {
			continue
		}
		f = m[t.String()]
		if f == nil {
			f = &TCPFlow{
				TCPTuple: t,
			}
			m[t.String()] = f
		}
		_ = f.AddPacket(d[i])
	}
	return m
}

// AddPacket updates the meta data for a TCPFlow and saves a reference to the
// pkt.Packet.  This assumes the packet addresses have been checked and the TCP
// flow matches (it does not check for matching addresses).
func (f *TCPFlow) AddPacket(p *pkt.Packet) error {
	ip, ok := p.Headers[pkt.NetworkLayer].(pkt.InetProtoHdr)
	if !ok || ip == nil {
		return ErrNetworkLayerHeader
	}
	tcpHdr, ok := p.Headers[pkt.TransportLayer].(*pkt.TcpHdr)
	if !ok || tcpHdr == nil {
		return ErrTransportLayerHeader
	}
	pt, err := NewTCPTuple(p)
	if err != nil {
		return err
	}
	var downstream = f.TCPTuple.Equal(pt)
	if p.Time.Before(f.StartTime) || f.StartTime.IsZero() {
		f.StartTime = p.Time
		if downstream {
			if f.SrcStartSeq > tcpHdr.Seq {
				f.SrcStartSeq = tcpHdr.Seq
			}
			if f.SrcStartAckSeq > tcpHdr.AckSeq {
				f.SrcStartAckSeq = tcpHdr.AckSeq
			}
		} else {
			if f.DstStartSeq > tcpHdr.Seq {
				f.DstStartSeq = tcpHdr.Seq
			}
			if f.DstStartAckSeq > tcpHdr.AckSeq {
				f.DstStartAckSeq = tcpHdr.AckSeq
			}
		}
	}
	if p.Time.After(f.EndTime) || f.EndTime.IsZero() {
		f.EndTime = p.Time
	}
	if downstream {
		f.SrcBytes += int64(p.Len)
		f.SrcPLBytes += int64(tcpHdr.PayloadLen(ip.PL()))
		f.SrcPktCnt++
	} else {
		f.DstBytes += int64(p.Len)
		f.DstPLBytes += int64(tcpHdr.PayloadLen(ip.PL()))
		f.DstPktCnt++
	}
	f.Data = append(f.Data, p)
	return nil
}
