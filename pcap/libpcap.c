// Copyright 2012 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// These are definitions that pcap.go needs.
#include "libpcap.h"

// Gets us the C function pointers that we need.

pt2cb getCallbackChan() {
  return (pt2cb)goCallbackChan;
}

pt2cb getCallbackLoop() {
  return (pt2cb)goCallbackLoop;
}

pt2cb getCallbackLoopAllocless() {
  return (pt2cb)goCallbackLoopAllocless;
}
