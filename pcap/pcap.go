// Copyright 2012 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !safe,!appengine

// The pcap package provides support for using the C pcap library from within a
// Go program.  Not all of the functions exported by <pacp.h> have been included
// in this package and more will be added on request.
//
package pcap

/*
#cgo linux LDFLAGS: -L../pcap -lpcap_linux
#cgo freebsd LDFLAGS: -L../pcap -lpcap_freebsd
#cgo darwin LDFLAGS: -L. -lpcap_darwin
#include <stdlib.h>
#include "pcap.h"
#include "libpcap.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"sync"
	"time"
	"unsafe"

	"github.com/VividCortex/golibpcap/pcap/pkt"
	"github.com/VividCortex/golibpcap/pcap/stat"
	"github.com/VividCortex/golibpcap/trace"
)

// Safe default values.  These are probably far from optimal for most systems.
const (
	DefaultBuffer  = int32(102400) // buffer limit
	DefaultPromisc = int32(1)      // 0->false, 1->true
	DefaultSnaplen = int32(65535)  // number of bytes to capture per packet.
	DefaultTimeout = int32(0)      // ms 0->no timeout
)

var (
	ChanBuffSize    = 5000 // How many packets can we buffer in our channel.
	OptimizeFilters = 1    // Tells the bpf compiler to optimize filters.
)

//export goCallbackChan
func goCallbackChan(user *C.u_char, pkthdr_ptr *C.struct_pcap_pkthdr, buf_ptr *C.u_char) {
	p := (*Pcap)(unsafe.Pointer(user))
	p.m.Lock()
	packet := pkt.NewPacket(unsafe.Pointer(pkthdr_ptr), unsafe.Pointer(buf_ptr))
	p.m.Unlock()
	p.Pchan <- packet
	p.pktCnt++
}

//export goCallbackLoop
func goCallbackLoop(user *C.u_char, pkthdr_ptr *C.struct_pcap_pkthdr, buf_ptr *C.u_char) {
	p := (*Pcap)(unsafe.Pointer(user))
	p.pktCnt++
	if p.datalinkType == 0 {
		p.datalinkType = p.Datalink()
	}
	if packet, err := pkt.NewPacket2(unsafe.Pointer(pkthdr_ptr), unsafe.Pointer(buf_ptr), p.datalinkType); err == nil {
		if p.loopCallback(packet) {
			p.BreakLoop()
		}
	}
}

//export goCallbackLoopAllocless
func goCallbackLoopAllocless(user *C.u_char, pkthdr_ptr *C.struct_pcap_pkthdr, buf_ptr *C.u_char) {
	p := (*Pcap)(unsafe.Pointer(user))
	p.pktCnt++
	if p.datalinkType == 0 {
		p.datalinkType = p.Datalink()
	}
	if pkt.NewPacketAllocless(unsafe.Pointer(pkthdr_ptr), unsafe.Pointer(buf_ptr), p.datalinkType, &p.Packet) {
		if p.loopCallback(&p.Packet) {
			p.BreakLoop()
		}
	}
}

// LibVersion returns information about the version of libpcap being used.
// Note that it contains more information than just a version number.
func LibVersion() string {
	return C.GoString(C.pcap_lib_version())
}

// Statustostr returns error strings for PCAP_ERROR_ and PCAP_WARNING_ values.
func Statustostr(errnum int32) string {
	return C.GoString(C.pcap_statustostr(C.int(errnum)))
}

// Pcap is the wrapper for the pcap_t struct in <pcap.h>.
type Pcap struct {
	FileName     string                    // Used for pcap_open_offline
	Device       string                    // Used for pcap_open_live
	Snaplen      int32                     // Specifies the maximum number of bytes to capture
	Promisc      int32                     // 0->false, 1->true
	Timeout      int32                     // ms
	Filters      []string                  // track filters applied to the capture
	Pchan        chan *pkt.Packet          // Channel for passing Packet pointers
	loopCallback func(*pkt.TcpPacket) bool // Callback for LoopWithCallback(), ret true to quit
	datalinkType int32                     // type of packets libpcap will send us
	cptr         *C.pcap_t                 // C Pointer to pcap_t
	Packet       pkt.TcpPacket             // used by alloc-less version of loop
	pktCnt       uint32                    // the number of packets captured
	m            *sync.Mutex               // Mutex to protect the packet memory for decode
}

// OpenOffline returns a *Pcap and opens it to read pcap packets from a save file.
func OpenOffline(file string) (*Pcap, error) {
	p := &Pcap{
		FileName: file,
		Pchan:    make(chan *pkt.Packet, ChanBuffSize),
		m:        &sync.Mutex{},
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
	p.Snaplen = int32(C.pcap_snapshot(p.cptr))
	return nil
}

// Create will construct a pcap that can be used to set custom settings like a
// larger buffer.  The resulting Pcap must then be started with a call to
// Activate.  See Open for an example list of calls that should be made.
func Create(device string) (*Pcap, error) {
	p := &Pcap{
		Device: device,
		Pchan:  make(chan *pkt.Packet, ChanBuffSize),
		m:      &sync.Mutex{},
	}

	buf := (*C.char)(C.calloc(C.PCAP_ERRBUF_SIZE, 1))
	defer C.free(unsafe.Pointer(buf))

	dev := C.CString(p.Device)
	defer C.free(unsafe.Pointer(dev))

	p.cptr = C.pcap_create(dev, buf)
	if p.cptr == nil {
		return p, errors.New(C.GoString(buf))
	}
	return p, nil
}

// OpenLive returns a *Pcap and opens it to listen to live network traffic.
func OpenLive(device string, snaplen int32, promisc bool, timeout_ms int32) (*Pcap, error) {
	p := &Pcap{
		Device:  device,
		Snaplen: snaplen,
		Timeout: timeout_ms,
		Pchan:   make(chan *pkt.Packet, ChanBuffSize),
		m:       &sync.Mutex{},
	}
	if promisc {
		p.Promisc = 1
	}
	return p, p.Open()
}

// Open creates a packet capture descriptor to look at packets on the network.
// Calling  C.pcap_open_live is the equivalent of calling:
//	C.pcap_create
//	C.pcap_set_snaplen
//	C.pcap_set_promisc
//	C.pcap_set_timeout
//	C.pcap_activate
//
// In that order.  So if you want to use custom values for any thing that has
// to be set before pcap is active you should use Create instead of Open or
// OpenLive.
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

// Close closes the files associated with p and deallocates C resources.
func (p *Pcap) Close() {
	if p.cptr != nil {
		p.m.Lock()
		C.pcap_close(p.cptr)
		p.m.Unlock()
	}
}

// Datalink returns the link layer type.
// For a list of possible DLT values see <pcap/bpf.h>.
func (p *Pcap) Datalink() int32 {
	return int32(C.pcap_datalink(p.cptr))
}

// GetErr returns an error based on the error text returned by pcap_geterr().
func (p *Pcap) GetErr() error {
	return errors.New(C.GoString(C.pcap_geterr(p.cptr)))
}

// SetSnaplen should only be called on a Pcap that was obtained through Create.
func (p *Pcap) SetSnaplen(snaplen int32) error {
	res := int32(C.pcap_set_snaplen(p.cptr, C.int(snaplen)))
	if res < 0 {
		return fmt.Errorf("%s(errnum=%d)", Statustostr(res), res)
	}
	p.Snaplen = snaplen
	return nil
}

// SetPromisc should only be called on a Pcap that was obtained through Create.
func (p *Pcap) SetPromisc(promisc bool) error {
	pro := int32(0)
	if promisc {
		pro = int32(1)
	}
	res := int32(C.pcap_set_promisc(p.cptr, C.int(pro)))
	if res < 0 {
		return fmt.Errorf("%s(errnum=%d)", Statustostr(res), res)
	}
	p.Promisc = pro
	return nil
}

// SetTimeout should only be called on a Pcap that was obtained through Create.
func (p *Pcap) SetTimeout(timeout_ms int32) error {
	res := int32(C.pcap_set_timeout(p.cptr, C.int(timeout_ms)))
	if res < 0 {
		return fmt.Errorf("%s(errnum=%d)", Statustostr(res), res)
	}
	p.Timeout = timeout_ms
	return nil
}

// SetBufferSize should only be called on a Pcap that was obtained through
// Create.  If the buffer size is too small then Activate will fail with a
// generic PCAP_ERROR.
func (p *Pcap) SetBufferSize(bufferSize int32) error {
	// If you try to set a negative buffer size
	// you are going to have a bad time.
	if bufferSize < 0 {
		return fmt.Errorf("negative buffer size")
	}
	res := int32(C.pcap_set_buffer_size(p.cptr, C.int(bufferSize)))
	if res < 0 {
		return fmt.Errorf("%s(errnum=%d)", Statustostr(res), res)
	}
	return nil
}

// Activate should only be called on a Pcap that was obtained through Create.
func (p *Pcap) Activate() error {
	res := int32(C.pcap_activate(p.cptr))
	if res < 0 {
		return fmt.Errorf("%s(errnum=%d)", Statustostr(res), res)
	}
	return nil
}

// Loop keeps reading packets until cnt packets are processed or an error occurs.
func (p *Pcap) Loop(cnt int) {
	C.pcap_loop(p.cptr, C.int(cnt), C.getCallbackChan(), (*C.u_char)(unsafe.Pointer(p)))
	p.Pchan <- nil
}

// Callback version of Loop().  CB signals to quit returning true.
// CB may keep packet if it calls Save().
func (p *Pcap) LoopWithCallback(cnt int, callback func(*pkt.TcpPacket) bool) {
	p.loopCallback = callback
	C.pcap_loop(p.cptr, C.int(cnt), C.getCallbackLoop(), (*C.u_char)(unsafe.Pointer(p)))
}

// Callback+allocless version of Loop().  CB signals to quit returning true.
// CB must not keep a ref to packet.  It can use Clone() to get its own copy.
func (p *Pcap) LoopWithCallbackAllocless(cnt int, callback func(*pkt.TcpPacket) bool) {
	p.loopCallback = callback
	C.pcap_loop(p.cptr, C.int(cnt), C.getCallbackLoopAllocless(), (*C.u_char)(unsafe.Pointer(p)))
}

// Listen will accumulate packets until it is stopped by a nil packet pointer.
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
	// pcap_breakloop will block while waiting on a packet to arrive after
	// it sets a flag to stop the loop.  This can be bad if you are calling
	// BreakLoop on a connection that has already disconnected.  For this
	// reason we are calling C.pcap_breakloop in another goroutine and
	// timing out after 1 ms.
	go C.pcap_breakloop(p.cptr)
	<-time.After(time.Millisecond)
	p.Pchan <- nil
}

// DelayBreakLoop stops the reading of packets after t seconds.
func (p *Pcap) DelayBreakLoop(t int) {
	<-time.After(time.Duration(t) * time.Second)
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
		p.m.Lock()
		packet := pkt.NewPacket(unsafe.Pointer(pkthdr_ptr), unsafe.Pointer(buf_ptr))
		p.m.Unlock()
		p.pktCnt++
		return packet, res
	}
	return nil, res
}

// NextEx2 is just like NextEx, but returns only TCP/IPv4 packets. This packet creates
// no new heap allocations unless the previous packet was "saved" (it's Save() member
// was called)
func (p *Pcap) NextEx2() (pkt.TcpPacket, int32) {
	var pkthdr_ptr *C.struct_pcap_pkthdr
	var buf_ptr *C.u_char
	var packet *pkt.TcpPacket
	var err error
	res := int32(C.pcap_next_ex(p.cptr, &pkthdr_ptr, &buf_ptr))
	if res == 1 {
		p.pktCnt++
		if p.datalinkType == 0 {
			p.datalinkType = p.Datalink()
		}
		if packet, err = pkt.NewPacket2(unsafe.Pointer(pkthdr_ptr), unsafe.Pointer(buf_ptr), p.datalinkType); err == nil {
			return *packet, res
		}
		res = 0
	}
	return pkt.TcpPacket{}, res
}

// Getstats returns a filled in Stat struct.
func (p *Pcap) Getstats() (*stat.Stat, error) {
	var cs C.struct_pcap_stat
	res := C.pcap_stats(p.cptr, &cs)
	if res == C.PCAP_ERROR {
		return nil, p.GetErr()
	}

	s := &stat.Stat{
		Captured:  p.pktCnt,
		Received:  uint32(cs.ps_recv),
		Dropped:   uint32(cs.ps_drop),
		IfDropped: uint32(cs.ps_ifdrop),
	}
	return s, nil
}

// Setfilter compiles a filter string into a bpf program and sets the filter.
func (p *Pcap) Setfilter(expr string) error {
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

	p.Filters = append(p.Filters, expr)

	C.pcap_freecode(&bpf)
	return nil
}

// NewPktTrace is a beta function and should be treated as such.
func (p *Pcap) NewPktTrace(data *[]*pkt.Packet) (*trace.PktTrace, error) {
	t := &trace.PktTrace{
		Version:    trace.Version,
		LibVersion: LibVersion(),
		Date:       time.Now(),
		MetaPcap: &trace.MetaPcap{
			Device:   p.Device,
			FileName: p.FileName,
			Snaplen:  p.Snaplen,
			Promisc:  p.Promisc,
			Timeout:  p.Timeout,
			Filters:  make([]string, len(p.Filters)),
		},
		Data: data,
	}
	for i := range p.Filters {
		t.MetaPcap.Filters[i] = p.Filters[i]
	}
	var err error
	t.Stats, err = p.Getstats()
	return t, err
}
