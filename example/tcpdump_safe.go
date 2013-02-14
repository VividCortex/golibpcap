// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build safe appengine

package main

import (
	"compress/gzip"
	"encoding/gob"
	"flag"
	"fmt"
	"log"
	"os"

	"code.google.com/p/golibpcap/trace"
)

// main reads a given gzip compressed gob encoded trace.PktTrace and displays
// some basic informtaiton about the trace to the console.
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
	gz, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		log.Fatalf("main:gzip.NewReader: %v", err)
	}
	gd := gob.NewDecoder(gz)
	t := &trace.PktTrace{}
	err = gd.Decode(t)
	if err != nil {
		gz.Close()
		f.Close()
		log.Fatalf("main:gd.Decode: %v", err)
	}
	err = gz.Close()
	if err != nil {
		log.Printf("main:gz.Close: %v", err)
	}
	err = f.Close()
	if err != nil {
		log.Printf("main:f.Close: %v", err)
	}
	fmt.Printf("Version: %s\n", t.Version)
	fmt.Printf("Date: %s\n", t.Date)
	fmt.Printf("Notes: %s\n", t.Notes)
	fmt.Printf("Stats: \n%s\n\n", t.Stats.String())
	fmt.Printf("MetaPcap.Device: %s\n", t.MetaPcap.Device)
	fmt.Printf("MetaPcap.Snaplen: %d\n", t.MetaPcap.Snaplen)
	fmt.Printf("MetaPcap.Promisc: %d\n", t.MetaPcap.Promisc)
	fmt.Printf("MetaPcap.Timeout: %d\n", t.MetaPcap.Timeout)
	fmt.Printf("MetaPcap.Filters: %v\n", t.MetaPcap.Filters)

}
