// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkt

/*
#include <sys/types.h>
#include <net/ethernet.h>
#include <netinet/in.h>
*/
import "C"
import (
	"net"
	"unsafe"
)

// The EthHdr struct is a wrapper for the ether_header struct in <net/ethernet.h>.
type EthHdr struct {
	cptr      *C.struct_ether_header // C pointer to ether_header
	SrcAddr   net.HardwareAddr       // the sender's MAC address
	DstAddr   net.HardwareAddr       // the receiver's MAC address
	EtherType uint16                 // packet type ID field
	payload   unsafe.Pointer
}

// With an unsafe.Pointer to the block of C memory NewEthHdr returns a filled in EthHdr struct.
func NewEthHdr(p unsafe.Pointer) (*EthHdr, unsafe.Pointer) {
	ethHdr := &EthHdr{
		cptr: (*C.struct_ether_header)(p),
	}
	ethHdr.SrcAddr = net.HardwareAddr(C.GoBytes(unsafe.Pointer(&ethHdr.cptr.ether_shost), C.ETHER_ADDR_LEN))
	ethHdr.DstAddr = net.HardwareAddr(C.GoBytes(unsafe.Pointer(&ethHdr.cptr.ether_dhost), C.ETHER_ADDR_LEN))
	ethHdr.EtherType = uint16(C.ntohs(C.uint16_t(ethHdr.cptr.ether_type)))

	// When using the Linux "any" device we have to handle cooked headers.
	// To determine if you could be in this case you can use pcap_datalink()
	// and check for DLT_LINUX_SLL.
	//TODO(gavaletz) This is an example of a decision that could be made once
	//   outside the process of decoding packets as if one is like this they
	//   will all be like this.
	if ethHdr.EtherType == 0 {
		// The "cooked" headers have an extra two bytes.
		ethHdr.payload = unsafe.Pointer(uintptr(p) + uintptr(C.ETHER_HDR_LEN) + uintptr(2))
	} else {
		ethHdr.payload = unsafe.Pointer(uintptr(p) + uintptr(C.ETHER_HDR_LEN))
	}
	return ethHdr, ethHdr.payload
}
