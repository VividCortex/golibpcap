// Copyright 2012 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin freebsd

package pkt

// See the testHelp.go file for the C data and the Go equivalents.

import (
	"testing"
)

// Make sure that we can properly parse a C TCP header.
func TestNewTcpHdr(t *testing.T) {
	g := goTcpTestHeader
	c, _ := NewTcpHdr(cTcpTestHeader)
	if c.Source != g.Source {
		t.Errorf("c.Source (%d) != g.Source (%d)", c.Source, g.Source)
	}
	if c.Dest != g.Dest {
		t.Errorf("c.Dest (%d) != g.Dest (%d)", c.Dest, g.Dest)
	}
	if c.Seq != g.Seq {
		t.Errorf("c.Seq (%d) != g.Seq (%d)", c.Seq, g.Seq)
	}
	if c.AckSeq != g.AckSeq {
		t.Errorf("c.AckSeq (%d) != g.AckSeq (%d)", c.AckSeq, g.AckSeq)
	}
	if c.Doff != g.Doff {
		t.Errorf("c.Doff (%d) != g.Doff (%d)", c.Doff, g.Doff)
	}
	if c.Flags != g.Flags {
		t.Errorf("c.Flags (%d) != g.Flags (%d)", c.Flags, g.Flags)
	}
	if c.Window != g.Window {
		t.Errorf("c.Window (%d) != g.Window (%d)", c.Window, g.Window)
	}
	if c.Check != g.Check {
		t.Errorf("c.Check (%d) != g.Check (%d)", c.Check, g.Check)
	}
	if c.UrgPtr != g.UrgPtr {
		t.Errorf("c.UrgPtr (%d) != g.UrgPtr (%d)", c.UrgPtr, g.UrgPtr)
	}
}

// Make sure the JSON output is good.
func TestJsonElement(t *testing.T) {
	if goTcpTestHeader.JsonElement() != goTcpJsonString {
		t.Error("goTcpTestHeader.JsonElement() != goTcpJsonString")
		t.Errorf("goTcpTestHeader.JsonElement() = `%s`", goTcpTestHeader.JsonElement())
	}
}

// Make sure the CSV output is good.
func TestCsvElement(t *testing.T) {
	if goTcpTestHeader.CsvElement() != goTcpCsvString {
		t.Error("goTcpTestHeader.CsvElement() != goTcpCsvString")
		t.Errorf("goTcpTestHeader.CsvElement() = `%s`", goTcpTestHeader.CsvElement())
	}
}

// Make sure the string output is good.
func TestString(t *testing.T) {
	if goTcpTestHeader.String() != goTcpString {
		t.Error("goTcpTestHeader.String() != goTcpString")
		t.Errorf("goTcpTestHeader.String() = `%s`", goTcpTestHeader.String())
	}
}
