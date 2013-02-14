// Copyright 2012 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This serves as an example of how to use of the Loop method for tracing a
// network interface.  Basically it is a very limited tcpdump.
//
// Example usage:
//
//	$ go build .
//	$ ./example -i eth0 -e="ip src 192.168.1.102"
//	$ ./example -r=pcapTrace.dat
//
// There is also the option to compile with the "safe" tag that will create
// a binary that does not rely on any system files or cgo.  This means that you
// can read and process trace.PktTrace files on any system that Go can be
// compiled for.  To compile and use this version of the binary use the command
//
//	$ go buiild -tags=safe .
//	$ ./example -r tracePktTraceFile.dat.gz
//
// Building and running the "safe" version will not allow you to capture packets
// but it will run on systems that don't have libpcap installed and will allow
// processing data on systems like appengine that don't allow the use of the
// unsafe package.
package main

import (
	"flag"
)

var (
	dumpFile *string = flag.String("r", "", "file to read")
)
