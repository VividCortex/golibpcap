// Copyright 2012 The golibpcap Authors. All rights reserved.                        
// Use of this source code is governed by a BSD-style                              
// license that can be found in the LICENSE file.

// The pcap package provides support for using the C pcap library from within a
// Go program.  Not all of the functions exported by <pacp.h> have been included
// in this package and more will be added on request.
//
package pcap

/*
#cgo LDFLAGS: -lpcap
#include <stdlib.h>
#include <pcap.h>
#include "libpcap.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"net"
	"time"
	"unsafe"

	"code.google.com/p/golibpcap/pcap/pkt"
)

var (
	ChanBuffSize    = 5000         // How many packets can we buffer in our channel.
	OptimizeFilters = 1            // Tells the bpf compiler to optimize filters.
	DefaultSnaplen  = int32(65535) // number of bytes to capture per packet.
	DefaultPromisc  = int32(1)     // 0->false, 1->true
)

// Represents the elements that go into a very common bpf filter.
//
// Most users can give the same filter strings that they would give to tcpdump
// directly to the Setfilter function.
type Filter struct {
	SrcIP   net.IP // The source IP address
	SrcPort int    // The source port number
	DstIp   net.IP // The destination IP address
	DstPort int    // The destination port number
}

// Given a complete Filter it generates the string form for Setfilter.
func (f *Filter) String() string {
	return fmt.Sprintf("ip src %s and src port %d and dst %s and dst port %d",
		f.SrcIP.String(),
		f.SrcPort,
		f.DstIp.String(),
		f.DstPort)
}

// Pcap is the wrapper for the pcap_t struct in <pcap.h>.
type Pcap struct {
	FileName string           // Used for pcap_open_offline
	Device   string           // Used for pcap_open_live
	Snaplen  int32            // Specifies the maximum number of bytes to capture
	Promisc  int32            // 0->false, 1->true
	Timeout  int32            // ms
	cptr     *C.pcap_t        // C Pointer to pcap_t
	pktCnt   uint32           // the number of packets captured
	Pchan    chan *pkt.Packet // Channel for passing Packet pointers
}

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

// LibVersion returns information about the version of libpcap being used.
// Note that it contains more information than just a version number.
func LibVersion() string {
	return C.GoString(C.pcap_lib_version())
}

// Datalink returns the link layer type.
// For a list of possible DLT values see <pcap/bpf.h>.
func (p *Pcap) Datalink() int {
	return int(C.pcap_datalink(p.cptr))
}

// GetErr returns an error based on the error text returned by pcap_geterr().
func (p *Pcap) GetErr() error {
	return errors.New(C.GoString(C.pcap_geterr(p.cptr)))
}

// Close closes a off-line pcap savefile.
func (p *Pcap) Close() {
	if p.FileName != "" {
		C.pcap_close(p.cptr)
	}
}

// OpenLive returns a *Pcap and opens it to listen to live network traffic.
func OpenLive(device string, snaplen int32, promisc bool, timeout_ms int32) (*Pcap, error) {
	p := &Pcap{
		Device:  device,
		Snaplen: snaplen,
		Timeout: timeout_ms,
		Pchan:   make(chan *pkt.Packet, ChanBuffSize),
	}
	if promisc {
		p.Promisc = 1
	}
	return p, p.Open()
}

// Open creates a packet capture descriptor to look at packets on the network.
func (p *Pcap) Open() error {
	buf := (*C.char)(C.calloc(C.PCAP_ERRBUF_SIZE, 1))
	defer C.free(unsafe.Pointer(buf))

	dev := C.CString(p.Device)
	defer C.free(unsafe.Pointer(dev))

	p.cptr = C.pcap_open_live(dev, C.int(p.Snaplen), C.int(p.Promisc),
		C.int(p.Timeout), buf)
	if p.cptr == nil {
		return errors.New(C.GoString(buf))
	}
	return nil
}

// OpenOffline returns a *Pcap and opens it to read pcap packets from a savefile.
func OpenOffline(file string) (*Pcap, error) {
	p := &Pcap{
		FileName: file,
		Pchan:    make(chan *pkt.Packet, ChanBuffSize),
	}

	return p, p.OpenFile()
}

// OpenFile opens a savefile for reading.
func (p *Pcap) OpenFile() error {
	var buf *C.char
	buf = (*C.char)(C.calloc(C.PCAP_ERRBUF_SIZE, 1))
	defer C.free(unsafe.Pointer(buf))

	cf := C.CString(p.FileName)
	defer C.free(unsafe.Pointer(cf))

	p.cptr = C.pcap_open_offline(cf, buf)
	if p.cptr == nil {
		return errors.New(C.GoString(buf))
	}
	//TODO(gavaletz) grab the file header information.
	return nil
}

//export goCallBack
func goCallBack(user *C.u_char, pkthdr_ptr *C.struct_pcap_pkthdr, buf_ptr *C.u_char) {
	packet := pkt.NewPacket(unsafe.Pointer(pkthdr_ptr), unsafe.Pointer(buf_ptr))
	p := (*Pcap)(unsafe.Pointer(user))
	p.Pchan <- packet
	p.pktCnt++
}

// Loop keeps reading packets until cnt packets are processed or an error occurs.
func (p *Pcap) Loop(cnt int) {
	C.pcap_loop(p.cptr, C.int(cnt), C.getCallback(), (*C.u_char)(unsafe.Pointer(p)))
	p.Pchan <- nil
}

func (p *Pcap) Listen(r chan *[]*pkt.Packet) {
	var b []*pkt.Packet
	for {
		packet := <-p.Pchan
		if packet == nil {
			break
		}
		b = append(b, packet)
	}
	r <- &b
}

// BreakLoop stops the reading of packets.
func (p *Pcap) BreakLoop() {
	C.pcap_breakloop(p.cptr)
	p.Pchan <- nil
}

// DelayBreakLoop stops the reading of packets after t seconds.
func (p *Pcap) DelayBreakLoop(t int) {
	time.Sleep(time.Duration(t) * time.Second)
	p.BreakLoop()
}

// Next is a wrapper for NextEx(). 
func (p *Pcap) Next() *pkt.Packet {
	rv, _ := p.NextEx()
	return rv
}

// NextEx reads the next packet and returns a success/failure indication:
//
//  1	the packet was read without problems
//  0	packets are being read from a live capture, and the timeout expired
// -1	an error occurred while reading the packet
// -2	packets are being read from a file, and there are no more packets to read
func (p *Pcap) NextEx() (*pkt.Packet, int32) {
	var pkthdr_ptr *C.struct_pcap_pkthdr
	var buf_ptr *C.u_char
	res := int32(C.pcap_next_ex(p.cptr, &pkthdr_ptr, &buf_ptr))
	if res == 1 {
		packet := pkt.NewPacket(unsafe.Pointer(pkthdr_ptr), unsafe.Pointer(buf_ptr))
		p.pktCnt++
		return packet, res
	}
	return nil, res
}

// Getstats returns a filled in Stat struct.
func (p *Pcap) Getstats() (*Stat, error) {
	var cs C.struct_pcap_stat
	res := C.pcap_stats(p.cptr, &cs)
	if res == C.PCAP_ERROR {
		return nil, p.GetErr()
	}

	s := &Stat{
		Captured:  p.pktCnt,
		Received:  uint32(cs.ps_recv),
		Dropped:   uint32(cs.ps_drop),
		IfDropped: uint32(cs.ps_ifdrop),
	}
	return s, nil
}

// Setfilter compiles a filter string into a bpf program and sets the filter.
func (p *Pcap) Setfilter(expr string) error {
	//TODO(gavaletz) figure out why this is not working off-line.
	cexpr := C.CString(expr)
	defer C.free(unsafe.Pointer(cexpr))

	var bpf C.struct_bpf_program
	res := C.pcap_compile(p.cptr, &bpf, cexpr, C.int(OptimizeFilters),
		C.PCAP_NETMASK_UNKNOWN)
	if res == C.PCAP_ERROR {
		return p.GetErr()
	}

	res = C.pcap_setfilter(p.cptr, &bpf)
	if res == C.PCAP_ERROR {
		C.pcap_freecode(&bpf)
		return p.GetErr()
	}

	C.pcap_freecode(&bpf)
	return nil
}
