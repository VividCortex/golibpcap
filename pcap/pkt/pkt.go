// Copyright 2012 The golibpcap Authors. All rights reserved.                      
// Use of this source code is governed by a BSD-style                              
// license that can be found in the LICENSE file.

// The pkt package provides access to the packet internals.                        
//
package pkt

import (
	"fmt"
	"strings"
)

// The Hdr interface allows us to deal with an array of headers.
type Hdr interface {
	JsonElement() string
	CsvElement() string
	String() string
}

// JsonString  returns a JSON encoding of the Packet struct.
func (p *Packet) JsonString() string {
	s := make([]string, len(p.Headers))
	for i := range p.Headers {
		s[i] = p.Headers[i].JsonElement()
	}
	return fmt.Sprintf("{\"time\":%d,%s}", p.Time.UnixNano(), strings.Join(s, ","))
}

// CsvString  returns a CSV encoding of the Packet struct.
// Each header type has a unique string that marks the beginning of the CSV
// fields for that particular header.
func (p *Packet) CsvString() string {
	s := make([]string, len(p.Headers))
	for i := range p.Headers {
		s[i] = p.Headers[i].CsvElement()
	}
	return fmt.Sprintf("%d,%s", p.Time.UnixNano(), strings.Join(s, ","))
}

// String returns a minimal encoding of the Packet struct.
func (p *Packet) String() string {
	s := make([]string, len(p.Headers))
	for i := range p.Headers {
		s[i] = p.Headers[i].String()
	}
	return fmt.Sprintf("%s %s", p.Time, strings.Join(s, " "))
}
