// Copyright 2012 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// These are definitions that pcap.go needs.
#include "libpcap.h"

// Calls the exported goCallBack function.
void callback(u_char *args, const struct pcap_pkthdr *header,
    const u_char *packet) {
  goCallBack(args, (struct pcap_pkthdr *)header, (u_char *)packet);
}

// Gets us the C function pointer that we need.
pt2cb getCallback(){
  return &callback;
}
