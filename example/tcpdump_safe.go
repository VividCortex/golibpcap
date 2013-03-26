// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build safe appengine

package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"code.google.com/p/golibpcap/trace"
)

// main reads a given gzip compressed gob encoded trace.PktTrace and displays
// some basic information about the trace to the console.
func main() {
	flag.Parse()

	if *dumpFile == "" {
		flag.Usage()
		log.Fatal("main: *dumpfile == \"\"")
	}
	f, err := os.Open(*dumpFile)
	if err != nil {
		log.Fatalf("main:os.Open: %v", err)
	}
	t, err := trace.PktTraceFromArchive(f)
	if err != nil {
		_ = f.Close()
		log.Fatalf("main:trace.PktTraceFromArchive: %v", err)
	}
	_ = f.Close()

	// Display aggregate stats and meta data for the trace.PktTrace.
	fmt.Printf("Version: %s\n", t.Version)
	fmt.Printf("LibVersion: %s\n", t.LibVersion)
	fmt.Printf("Date: %s\n", t.Date)
	fmt.Printf("Notes: %s\n", t.Notes)
	if t.Stats != nil {
		fmt.Printf("Stats: \n%s\n\n", t.Stats.String())
	}
	fmt.Printf("MetaPcap.Device: %s\n", t.MetaPcap.Device)
	fmt.Printf("MetaPcap.FileName: %s\n", t.MetaPcap.FileName)
	fmt.Printf("MetaPcap.Snaplen: %d\n", t.MetaPcap.Snaplen)
	fmt.Printf("MetaPcap.Promisc: %d\n", t.MetaPcap.Promisc)
	fmt.Printf("MetaPcap.Timeout: %d\n", t.MetaPcap.Timeout)
	fmt.Printf("MetaPcap.Filters: %v\n", t.MetaPcap.Filters)

	// Display aggregate stats for the IP headers from the trace.PktTrace.
	m := trace.GetIPTraffic(*t.Data)
	for k, v := range m {
		fmt.Printf("%s -- %d %d-%d %d %d\n", k, len(v.Data),
			v.StartTime.Unix(), v.EndTime.Unix(),
			v.Bytes, v.PLBytes)
	}

	// Display aggregate stats for the TCP headers from the trace.PktTrace.
	tcpMap := trace.GetTCPTraffic(*t.Data)
	for k, v := range tcpMap {
		fmt.Printf("%s -- %d %d-%d %d %d\n", k, len(v.Data),
			v.StartTime.Unix(), v.EndTime.Unix(),
			v.SrcPktCnt, v.DstPktCnt)
	}
}
