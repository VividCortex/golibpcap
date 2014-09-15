// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build darwin freebsd

package pkt

/*
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
*/
import "C"
import (
	"unsafe"
)

func getIphdr(buf_ptr unsafe.Pointer) *C.struct_ip {
	return (*C.struct_ip)(buf_ptr)
}

func getPaylen(iphdr *C.struct_ip) uint16 {
	return uint16(iphdr.ip_len)
}

func getProtocol(iphdr *C.struct_ip) uint8 {
	return uint8(iphdr.ip_p)
}
