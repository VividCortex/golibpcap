// Copyright 2012 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This serves as an example of how to use of the Loop method for tracing a
// network interface.  Basically it is a very limited tcpdump.
//
// Example usage:
//
//	$ go build tcpdump.go
//	$ ./tcpdump -i eth0 -e="ip src 192.168.1.102"
//	$ ./tcpdump -r=pcapTrace.dat
//
package main

import (
	"flag"
	"fmt"
	"log"

	"code.google.com/p/golibpcap/pcap"
)

var (
	device   *string = flag.String("i", "eth0", "interface")
	expr     *string = flag.String("e", "", "filter expression")
	dumpFile *string = flag.String("r", "", "pcap savefile to read")
	verbose  *bool   = flag.Bool("v", false, "use verbose outupt")
	pCount   *int    = flag.Int("c", 0, "packet count")
	snaplen  *int    = flag.Int("s", 65535, "snaplen")
	tLimit   *int    = flag.Int("t", 0, "time limit")
)

func main() {

	flag.Parse()

	var h *pcap.Pcap
	var err error

	// First we check to see if the user is passing us a pcap savefile to
	// read.  If so, then we will open that offline.
	if *dumpFile != "" {
		h, err = pcap.OpenOffline(*dumpFile)
		if err != nil {
			log.Fatalf("main:pcap.OpenOffline: %v", err)
		}
	}

	if h == nil {
		if *device == "" {
			flag.Usage()
			log.Fatal("main: *device == \"\"")
		}
		// Given a device we will open a live trace of that device.
		h, err = pcap.OpenLive(*device, int32(*snaplen), true, 0)
		if err != nil {
			log.Fatalf("main:pcap.OpenLive: %v", err)
		}
	}

	// If given a filter string to use then try to apply that filter.
	if *expr != "" {
		err = h.Setfilter(*expr)
		if err != nil {
			log.Fatalf("main:h.Setfilter: %v", err)
		}
	}

	// If given a fixed amount of time to trace the device then start a
	// goroutine that will terminate the live capture after that amount of
	// time.
	if *tLimit > 0 {
		go h.DelayBreakLoop(*tLimit)
	}

	// If given a fixed number of packets to grab them just grab that many
	// otherwise we should enter an loop that does not end.  In the latter
	// case either the time limit will trigger an exit or the program will
	// have to be killed by an external force.
	if *pCount > 0 {
		go h.Loop(*pCount)
	} else {
		go h.Loop(-1)
	}

	// Start decoding packets until we receive the signal to stop (nil pkt).
	if *verbose {
		for {
			pkt := <-h.Pchan
			if pkt == nil {
				break
			}
			fmt.Println(pkt.JsonString())
		}
		s, err := h.Getstats()
		if err == nil {
			fmt.Printf("%s\n", s)
		}
	} else {
		for {
			pkt := <-h.Pchan
			if pkt == nil {
				break
			}
			fmt.Println(pkt.String())
		}
		s, err := h.Getstats()
		if err == nil {
			fmt.Printf("%s\n", s)
		}
	}
}
