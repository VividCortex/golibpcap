// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build !safe,!appengine

package main

import (
	"flag"
	"fmt"
	"log"

	"code.google.com/p/golibpcap/pcap"
)

var (
	device    *string = flag.String("i", "", "interface")
	expr      *string = flag.String("e", "", "filter expression")
	buffLimit *int    = flag.Int("b", 0, "buffer limit (>=102400)")
	pCount    *int    = flag.Int("c", 0, "packet count")
	snaplen   *int    = flag.Int("s", 65535, "snaplen")
	tLimit    *int    = flag.Int("t", 0, "time limit")
	quiet     *bool   = flag.Bool("q", false, "use quiet outupt (stats only)")
	verbose   *bool   = flag.Bool("v", false, "use verbose outupt")
)

// main uses golibpcap to build a simple tcpdump binary.
func main() {
	flag.Parse()

	var h *pcap.Pcap
	var err error

	// First we check to see if the user is passing us a pcap save file to
	// read.  If so, then we will open that off-line.
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
		if *buffLimit != 0 {
			// If we have a custom buffer limit then we have to set things up
			// by hand.  Most of these settings have to be set before and cannot
			// be changed once the pcap is active.
			h, err = pcap.Create(*device)
			if err != nil {
				log.Fatalf("main:pcap.Create: %v", err)
			}
			err = h.SetSnaplen(int32(*snaplen))
			if err != nil {
				log.Fatalf("main:h.SetSnaplen: %v", err)
			}
			err = h.SetBufferSize(int32(*buffLimit))
			if err != nil {
				log.Fatalf("main:h.SetBufferSize: %v", err)
			}
			err = h.SetPromisc(true)
			if err != nil {
				log.Fatalf("main:h.SetPromisc: %v", err)
			}
			err = h.SetTimeout(int32(0))
			if err != nil {
				log.Fatalf("main:h.SetTimeout: %v", err)
			}
			err = h.Activate()
			if err != nil {
				log.Fatalf("main:h.Activate: %v", err)
			}
		}
	}
	if h == nil {
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
	} else if *quiet {
		for {
			pkt := <-h.Pchan
			if pkt == nil {
				break
			}
		}
	} else {
		for {
			pkt := <-h.Pchan
			if pkt == nil {
				break
			}
			fmt.Println(pkt.String())
		}
	}
	s, err := h.Getstats()
	if err == nil {
		fmt.Printf("%s\n", s)
	}
}
