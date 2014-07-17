// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pkt

import (
	"reflect"
	"unsafe"
)

// GetPayloadBytes returns the bytes from the packet's payload.  This is a Go
// slice backed by the C bytes.  The result is that the Go slice uses very
// little extra memory.
func (h *UdpHdr) GetPayloadBytes(pl uint16) []byte {
	l := int(h.PayloadLen(pl))
	if l <= 0 {
		return []byte{}
	}
	var b []byte
	sh := (*reflect.SliceHeader)((unsafe.Pointer(&b)))
	sh.Cap = l
	sh.Len = l
	sh.Data = uintptr(h.payload)
	return b
}
