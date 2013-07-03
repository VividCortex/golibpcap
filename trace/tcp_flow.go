// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trace

import (
	"fmt"
	"time"

	"github.com/VividCortex/golibpcap/pcap/pkt"
)

// A TCPFlow makes working with TCP data easier.
type TCPFlow struct {
	TCPTuple       *TCPTuple              // The source and destination addresses
	Data           []*pkt.Packet          // The array of packets
	StartTime      time.Time              // Time of the first packet
	EndTime        time.Time              // Time of the last packet
	SrcFirstSeq    uint32                 // The first seq number in the flow
	DstFirstSeq    uint32                 // The first seq number in the flow
	SrcFirstAckSeq uint32                 // The first ACK seq number in the flow
	DstFirstAckSeq uint32                 // The first ACK seq number in the flow
	SrcBytes       int64                  // Number of application bytes Src->Dst
	DstBytes       int64                  // Number of application bytes Dst->Src
	SrcPLBytes     int64                  // Number of IP payload bytes Src->Dst
	DstPLBytes     int64                  // Number of IP payload bytes Dst->Src
	SrcWireBytes   int64                  // Number of off the wire bytes Src->Dst
	DstWireBytes   int64                  // Number of off the wire bytes Dst->Src
	SrcPktCnt      int64                  // Number of packets Src->Dst
	DstPktCnt      int64                  // Number of packets Dst->Src
	SrcData        []*pkt.Packet          // An array of packets Src->Dst
	DstData        []*pkt.Packet          // An array of packets Dst->Src
	SrcDataMap     map[uint32]*pkt.Packet // A map of seq to packets Src->Dst
	DstDataMap     map[uint32]*pkt.Packet // A map of seq to packets Dst->Src
}

// NewTCPFlow filters the packet in d by t.MatchFlow and returns the resulting
// TCPFlow for analysis.
func NewTCPFlow(d []*pkt.Packet, t *TCPTuple) *TCPFlow {
	f := &TCPFlow{
		TCPTuple:   t,
		SrcDataMap: make(map[uint32]*pkt.Packet),
		DstDataMap: make(map[uint32]*pkt.Packet),
	}
	f.AddData(d)
	return f
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
				TCPTuple:   t,
				SrcDataMap: make(map[uint32]*pkt.Packet),
				DstDataMap: make(map[uint32]*pkt.Packet),
			}
			m[t.String()] = f
		}
		_ = f.AddPacket(d[i])
	}
	return m
}

// AddData will call f.AddPacket for each packet in d where f.TCPTuple.MatchFlow
// is true.  This is a faster way to create a TCPFlow if you know you are only
// interested in the TCP traffic for a single TCPTuple.
func (f *TCPFlow) AddData(d []*pkt.Packet) {
	for i := range d {
		t, err := NewTCPTuple(d[i])
		if err != nil {
			continue
		}
		if t.MatchFlow(f.TCPTuple) {
			_ = f.AddPacket(d[i])
		}
	}
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
			if f.SrcFirstSeq > tcpHdr.Seq {
				f.SrcFirstSeq = tcpHdr.Seq
			}
			if f.SrcFirstAckSeq > tcpHdr.AckSeq {
				f.SrcFirstAckSeq = tcpHdr.AckSeq
			}
		} else {
			if f.DstFirstSeq > tcpHdr.Seq {
				f.DstFirstSeq = tcpHdr.Seq
			}
			if f.DstFirstAckSeq > tcpHdr.AckSeq {
				f.DstFirstAckSeq = tcpHdr.AckSeq
			}
		}
	}
	if p.Time.After(f.EndTime) || f.EndTime.IsZero() {
		f.EndTime = p.Time
	}
	if downstream {
		f.SrcBytes += int64(tcpHdr.PayloadLen(ip.PL()))
		f.SrcPLBytes += int64(ip.PL())
		f.SrcWireBytes += int64(p.Len)
		f.SrcPktCnt++
		f.SrcData = append(f.SrcData, p)
		f.SrcDataMap[tcpHdr.Seq] = p
	} else {
		f.DstBytes += int64(tcpHdr.PayloadLen(ip.PL()))
		f.DstPLBytes += int64(ip.PL())
		f.DstWireBytes += int64(p.Len)
		f.DstPktCnt++
		f.DstData = append(f.DstData, p)
		f.DstDataMap[tcpHdr.Seq] = p
	}
	f.Data = append(f.Data, p)
	return nil
}

// Analyze computes the aggregate packet-level data for a TCPFlow.  This does
// not take into account packets that may have been dropped by the pcap trace
// and the analysis of such traces will be less accurate than those without any
// missing packets.
func (f *TCPFlow) Analyze() (*TCPFlowStats, error) {
	return TCPFlowAnalysis(f.Data, f.TCPTuple)
}

// Aggregate packet-level data for a TCPFlow.  This is usually returned from a
// call to TCPFlow.Analysis().
type TCPFlowStats struct {
	DstDupAck    int    // Total number of duplicate Dst ACKs
	DstLoss      int    // Number retransmitted Dst packets
	DstLossBytes uint32 // Number of retransmitted Dst bytes
	DstOrder     int    // Number of out-of-order Dst packets
	DstOther     int    // Number of other non-normal Dst packets
	SrcDupAck    int    // Total number of duplicate Src ACKs sent
	SrcLoss      int    // Number retransmitted Src packets
	SrcLossBytes uint32 // Number of retransmitted Src bytes
	SrcOrder     int    // Number of out-of-order Src packets
	SrcOther     int    // Number of other non-normal Src packets
}

// Analysis computes the aggregate packet-level data for a TCPFlow.  This does
// not take into account packets that may have been dropped by the pcap trace
// and the analysis of such traces will be less accurate than those without any
// missing packets.
func TCPFlowAnalysis(d []*pkt.Packet, t *TCPTuple) (*TCPFlowStats, error) {
	var (
		ip           pkt.InetProtoHdr // IP header - to access the IP payload length
		tcp          *pkt.TcpHdr      // TCP header - to gather per-packet tcp data
		ok           bool             // caste success indicator
		pl           uint16           // TCP payload length
		srcSeq       uint32           // the expected Dst sequence number
		dstSeq       uint32           // the expected Dst sequence number
		srcAck       uint32           // the last Src ACK sequence number
		dstAck       uint32           // the last Dst ACK sequence number
		srcDupAckCnt int              // count of Src ACK duplicates
		dstDupAckCnt int              // count of Dst ACK duplicates
	)
	fs := &TCPFlowStats{}           // accumulation of stats
	srcLoss := make(map[uint32]int) // accumulation of Src losses
	dstLoss := make(map[uint32]int) // accumulation of Dst losses
	for i := range d {
		ip, ok = d[i].Headers[pkt.NetworkLayer].(pkt.InetProtoHdr)
		if !ok || ip == nil {
			return fs, ErrNetworkLayerHeader
		}
		tcp, ok = d[i].Headers[pkt.TransportLayer].(*pkt.TcpHdr)
		if !ok || tcp == nil {
			return fs, ErrTransportLayerHeader
		}
		pl = tcp.PayloadLen(ip.PL())
		if int(tcp.Source) == t.Src.Port {
			if tcp.AckSeq > srcAck {
				srcAck = tcp.AckSeq
				srcDupAckCnt = 0
			} else if tcp.AckSeq == srcAck {
				srcDupAckCnt++
				fs.SrcDupAck++
				if srcDupAckCnt == 3 && srcAck != dstSeq {
					dstLoss[srcAck] = i
				}
			}
			if tcp.Seq >= srcSeq {
				srcSeq = tcp.Seq + uint32(pl)
			} else {
				_, ok = srcLoss[tcp.Seq]
				if ok {
					fs.SrcLoss++
					fs.SrcLossBytes += uint32(pl)
					delete(srcLoss, tcp.Seq)
				} else {
					if dstDupAckCnt < 3 {
						fs.SrcOrder++
					} else {
						fs.SrcOther++
					}
				}
			}
		} else {
			if tcp.AckSeq > dstAck {
				dstAck = tcp.AckSeq
				dstDupAckCnt = 0
			} else if tcp.AckSeq == dstAck {
				dstDupAckCnt++
				fs.DstDupAck++
				if dstDupAckCnt == 3 && dstAck != srcSeq {
					srcLoss[dstAck] = i
				}
			}
			if tcp.Seq >= dstSeq {
				dstSeq = tcp.Seq + uint32(pl)
			} else {
				_, ok = dstLoss[tcp.Seq]
				if ok {
					fs.DstLoss++
					fs.DstLossBytes += uint32(pl)
					delete(dstLoss, tcp.Seq)
				} else {
					if srcDupAckCnt < 3 {
						fs.DstOrder++
					} else {
						fs.DstOther++
					}
				}
			}
		}
	}
	fs.DstOther += len(dstLoss)
	fs.SrcOther += len(srcLoss)
	return fs, nil
}

//TODO(gavaletz) func RTT(d []*pkt.Packet) (int64, error)

// getBytes returns the total number of bytes from the IP payload length
// for a given range of packets where s is a valid TCP sequence number for the
// beginning of the range and e is a valid TCP sequence number for the end of the
// range.  The pm map is used to lookup packets for every sequence number in the
// range s to e; this map should be obtained as part of a TCPFlow.
func getBytes(s, e uint32, pm map[uint32]*pkt.Packet) (uint32, error) {
	var (
		ip  pkt.InetProtoHdr // IP header - to access the IP payload length
		tcp *pkt.TcpHdr      // TCP header - to gather per-packet TCP data
		ok  bool             // caste success indicator
		seq uint32           // the expected sequence number
		b   uint32           // total number of bytes
		pl  uint32           // TCP payload length
		p   *pkt.Packet
	)
	seq = s
	for {
		if seq > e {
			break
		}
		p, ok = pm[seq]
		if !ok || p == nil {
			if seq == e {
				//TODO(gavaletz) Hack for last AcKSeq in a trace.
				break
			}
			return b, ErrTCPSeqMissing
		}
		tcp, ok = p.Headers[pkt.TransportLayer].(*pkt.TcpHdr)
		if !ok || tcp == nil {
			return b, ErrTransportLayerHeader
		}
		ip, ok = p.Headers[pkt.NetworkLayer].(pkt.InetProtoHdr)
		if !ok || ip == nil {
			return b, ErrNetworkLayerHeader
		}
		pl = uint32(tcp.PayloadLen(ip.PL()))
		b += pl
		if pl < 1 {
			return b, ErrTCPSeqMissing
		}
		seq += pl
	}
	return b, nil
}

// ACKTimes returns the timestamps and ACK sequence numbers that are strictly
// increasing within d.
func ACKTimes(d []*pkt.Packet) ([]time.Time, []uint32, error) {
	var t []time.Time
	var a []uint32
	var tcp *pkt.TcpHdr
	var ok bool
	var ack uint32
	for i := range d {
		tcp, ok = d[i].Headers[pkt.TransportLayer].(*pkt.TcpHdr)
		if !ok || tcp == nil {
			return t, a, ErrTransportLayerHeader
		}
		if tcp.AckSeq > ack {
			t = append(t, d[i].Time)
			a = append(a, tcp.AckSeq)
			ack = tcp.AckSeq
		}
	}
	return t, a, nil
}

// SeqTimes returns the timestamps and sequence numbers that are strictly
// increasing within d.
func SEQTimes(d []*pkt.Packet) ([]time.Time, []uint32, error) {
	var t []time.Time
	var a []uint32
	var tcp *pkt.TcpHdr
	var ok bool
	var seq uint32
	for i := range d {
		tcp, ok = d[i].Headers[pkt.TransportLayer].(*pkt.TcpHdr)
		if !ok || tcp == nil {
			return t, a, ErrTransportLayerHeader
		}
		if tcp.Seq > seq {
			t = append(t, d[i].Time)
			a = append(a, tcp.Seq)
			seq = tcp.Seq
		}
	}
	return t, a, nil
}

func throughputBitsPerNS(t time.Duration, b uint32) float64 {
	return float64(b) * float64(8) / float64(t)
}

func throughputMbps(t time.Duration, b uint32) float64 {
	return float64(b) * float64(0.000008) / t.Seconds()
}

func throughputGbps(t time.Duration, b uint32) float64 {
	return float64(b) * float64(0.000000008) / t.Seconds()
}

type thrCal func(time.Duration, uint32) float64
type pSel func([]*pkt.Packet) ([]time.Time, []uint32, error)

//TODO(gavaletz) Make sure this conforms to the standards in RFC3148.
func throughput(d []*pkt.Packet, sl pSel, tc thrCal) ([]time.Duration, []float64, error) {
	var x []time.Duration
	var y []float64
	t, p, err := sl(d)
	if err != nil {
		return x, y, err
	}
	x = make([]time.Duration, len(t))
	y = make([]float64, len(t))
	for i := 1; i < len(t); i++ {
		x[i] = t[i].Sub(t[0])
		y[i] = tc(t[i].Sub(t[i-1]), p[i]-p[i-1])
	}
	return x, y, nil
}

//TODO(gavaletz) Make sure this conforms to the standards in RFC5136.
// This should use a start and end time and an IPFlow or the raw trace.
// That may not be so simple with the ACK direction as we are inferring what
// arrived in tact.
func capacity(d []*pkt.Packet, pm map[uint32]*pkt.Packet, sl pSel, tc thrCal) ([]time.Duration, []float64, error) {
	var x []time.Duration
	var y []float64
	var b uint32
	t, p, err := sl(d)
	if err != nil {
		return x, y, err
	}
	x = make([]time.Duration, len(t))
	y = make([]float64, len(t))
	for i := 1; i < len(t); i++ {
		x[i] = t[i].Sub(t[0])
		b, err = getBytes(p[i-1], p[i], pm)
		if err != nil {
			return x, y, err
		}
		y[i] = tc(t[i].Sub(t[i-1]), b)
	}
	return x, y, nil
}

// ACKThroughput calculates the throughput in bits per nanosecond for every
// monotonically increasing ACK in d.  The resulting slices are suitable for use
// as the x and y values in a plot of throughput vs. time.
func ACKThroughput(d []*pkt.Packet) ([]time.Duration, []float64, error) {
	return throughput(d, ACKTimes, throughputBitsPerNS)
}

// SEQThroughput calculates the throughput in bits per nanosecond for every
// monotonically increasing sequence number  in d.  The resulting slices are
// suitable for use as the x and y values in a plot of throughput vs. time.
func SEQThroughput(d []*pkt.Packet) ([]time.Duration, []float64, error) {
	return throughput(d, SEQTimes, throughputBitsPerNS)
}

// ACKCapacity calculates the IP capacity in bits per nanosecond for every
// monotonically increasing ACK in d.  The resulting slices are suitable for use
// as the x and y values in a plot of IP capacity vs. time.
func ACKCapacity(d []*pkt.Packet, pm map[uint32]*pkt.Packet) ([]time.Duration, []float64, error) {
	return capacity(d, pm, ACKTimes, throughputBitsPerNS)
}

// SEQCapacity calculates the IP capacity in bits per nanosecond for every
// monotonically increasing sequence number  in d.  The resulting slices are
// suitable for use as the x and y values in a plot of IP capacity vs. time.
func SEQCapacity(d []*pkt.Packet, pm map[uint32]*pkt.Packet) ([]time.Duration, []float64, error) {
	return capacity(d, pm, SEQTimes, throughputBitsPerNS)
}

// TCPDataDump provides text debugging information for all the TCP packets in d.
// A result that returns with an error may still have partial information up to
// the packet that caused the error.
func TCPDataDump(d []*pkt.Packet) ([]string, error) {
	var tcpHdr *pkt.TcpHdr
	var ipHdr pkt.InetProtoHdr
	var ok bool
	pl := make([]string, len(d))
	for i := range d {
		ipHdr, ok = d[i].Headers[pkt.NetworkLayer].(pkt.InetProtoHdr)
		if !ok || ipHdr == nil {
			return pl, ErrNetworkLayerHeader
		}
		tcpHdr, ok = d[i].Headers[pkt.TransportLayer].(*pkt.TcpHdr)
		if !ok || tcpHdr == nil {
			return pl, ErrTransportLayerHeader
		}
		pl[i] = fmt.Sprintf("%d %d->%d %d %d %d %#x %d %d",
			d[i].Time.UnixNano(),
			tcpHdr.Source,
			tcpHdr.Dest,
			tcpHdr.Seq,
			tcpHdr.AckSeq,
			tcpHdr.Doff,
			tcpHdr.Flags,
			tcpHdr.Window,
			tcpHdr.PayloadLen(ipHdr.PL()))
	}
	return pl, nil
}

// TCPContextDump provides debugging information for d[l] with up to c lines of
// context.  The int is the index of the d[l] within the context.  A result that
// returns with an error may still have d[l] with partial context.
func TCPContextDump(d []*pkt.Packet, l, c int) ([]string, int, error) {
	i := 2*l - c
	s := l - c
	if s < 0 {
		s = 0
	}
	e := l + c
	if i > len(d) {
		e = len(d)
	}
	r, err := TCPDataDump(d[s:e])
	return r, i, err
}
