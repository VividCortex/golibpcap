// Copyright 2012 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// These are definitions that pcap.go needs.
#include <stdlib.h>
#include "pcap.h"

// Defined in pcap.go
extern void goCallBack(u_char *, struct pcap_pkthdr *, u_char *);

// Calls the exported goCallBack function.
void callback(u_char *, const struct pcap_pkthdr *, const u_char *);

typedef void(*pt2cb)(u_char *, const struct pcap_pkthdr *, const u_char *);

// Gets us the C function pointer that we need.
pt2cb getCallback();
