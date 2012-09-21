// Copyright 2012 The golibpcap Authors. All rights reserved.                      
// Use of this source code is governed by a BSD-style                              
// license that can be found in the LICENSE file.

package pkt

// C constants to be used in unit tests.  Go's test runner will not run files
// that import "test" if they also import "C" so we had to move them to a
// different file.  Since we want these things kept together the Go versions
// that should match these values are in this file too.

/*
#include <netinet/in.h>
#include <netinet/tcp.h>

// Our test TCP header.
struct tcphdr h = {};

// Returns the address of our test TCP header.
struct tcphdr * getTcpHeader() {
  h.source = htons(81);
  h.dest = htons(82);
  h.seq = htonl(424242);
  h.ack_seq = htonl(313131);
  h.res1 = 0;
  h.doff = sizeof(struct tcphdr) >> 2;
  h.fin = 0;
  h.syn = 0;
  h.rst = 0;
  h.psh = 0;
  h.ack = 1;
  h.urg = 0;
  h.res2 = 0;
  h.window = htons(512);
  h.check = htons(9999);
  h.urg_ptr = htons(777);

  return &h;
}
*/
import "C"
import (
	"unsafe"
)

// The address of the above C struct.
var cTcpTestHeader = unsafe.Pointer(C.getTcpHeader())

// Test values to match the C struct above.
var goTcpTestHeader = &TcpHdr{
	cptr:   C.getTcpHeader(),
	Source: 81,
	Dest:   82,
	Seq:    424242,
	AckSeq: 313131,
	Doff:   5,
	Flags:  2,
	Window: 512,
	Check:  9999,
	UrgPtr: 777,
}

// Test values that should match the output for the above C struct
const (
	goTcpJsonString = `"tcphdr":{"source":81,"dest":82,"seq":424242,"ack_seq":313131,"flags":2}`
	goTcpCsvString  = `"TCP",81,82,424242,313131,2`
	goTcpString     = "81->82 424242 313131 0x2"
)
