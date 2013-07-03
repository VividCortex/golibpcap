// Copyright 2013 The golibpcap Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package trace

import (
	"net"

	"github.com/VividCortex/golibpcap/pcap/pkt"
)

// A HTTPExchange makes working with HTTP data easier.  The TCPTuple will have
// the Dst set as the address that is sending the request, and the Src as the
// address that responds.  The data will always have the packet that contains
// the request as Data[0].
//
// For now this is not designed to work well on pipelined responses.
type HTTPExchange struct {
	TCPTuple    *TCPTuple     // The source and destination addresses
	ReqHTTPHdr  *pkt.HttpHdr  // The HTTP request Header
	RespHTTPHdr *pkt.HttpHdr  // The HTTP response Header
	Data        []*pkt.Packet // The array of packets
	Resp        int           // The beginning of the HTTP response
}

// NewHTTPExchange creates and returns a HTTPExchange with the given packet data.
// it is important that the packet with the HTTP request be present in d[0], and
// it is assumed that the ACK for the last packet of response is in d[len(d)-1].
// Having a valid respIndex for the first packet of the response containing the 
// HTTP response header will speed this up, if it is not valid (<0 if unknown)
// then this method will search for it.  The Data for the HTTPExchange is a
// slice backed by the same array as d.
//
// This method does not check the rest of d to make sure that the packets are in
// fact part of this transfer, so only pass what should be used.
func NewHTTPExchange(d []*pkt.Packet, respIndex int) (*HTTPExchange, error) {
	var (
		httpHdr *pkt.HttpHdr // HTTP header - to gather per-packet HTTP data
		ok      bool         // caste success indicator
	)
	e := &HTTPExchange{
		TCPTuple: &TCPTuple{
			Src: &net.TCPAddr{},
			Dst: &net.TCPAddr{},
		},
		Data: d,
		Resp: -1,
	}
	if len(d) == 0 {
		return e, ErrEmptyData
	}
	if len(d[0].Headers) > ApplicationLayer {
		ip, ok := d[0].Headers[pkt.NetworkLayer].(pkt.InetProtoHdr)
		if !ok || ip == nil {
			return e, ErrNetworkLayerHeader
		}
		tcp, ok := d[0].Headers[pkt.TransportLayer].(*pkt.TcpHdr)
		if !ok || tcp == nil {
			return e, ErrTransportLayerHeader
		}
		httpHdr, ok = d[0].Headers[ApplicationLayer].(*pkt.HttpHdr)
		if !ok || httpHdr == nil || httpHdr.StatusCode != 0 {
			return e, ErrApplicationLayerHeader
		}
		// We don't use the NewTCPTuple method here because we want to
		// swap the Src and Dst.
		e.TCPTuple.Dst.IP = ip.Src()
		e.TCPTuple.Src.IP = ip.Dst()
		e.TCPTuple.Dst.Port = int(tcp.Source)
		e.TCPTuple.Src.Port = int(tcp.Dest)
		e.ReqHTTPHdr = httpHdr
	} else {
		return e, ErrApplicationLayerHeader
	}
	if respIndex > 0 && respIndex < len(d) {
		if len(d[respIndex].Headers) > ApplicationLayer {
			httpHdr, ok = d[respIndex].Headers[ApplicationLayer].(*pkt.HttpHdr)
			if ok {
				e.Resp = respIndex
				e.RespHTTPHdr = httpHdr
				return e, nil
			}
		}
	}
	// We got an invalid respIndex so we will have to look for it here.
	for i := 1; i < len(d); i++ {
		if len(d[i].Headers) > ApplicationLayer {
			httpHdr, ok = d[i].Headers[ApplicationLayer].(*pkt.HttpHdr)
			if ok {
				if httpHdr.StatusCode > 0 {
					e.Resp = respIndex
					e.RespHTTPHdr = httpHdr
					return e, nil
				}
			}
		}
	}
	return e, nil
}

// GetHTTPTraffic parses the packets in d []*pkt.Packet looking for *pkt.HttpHdr,
// When one is found we slice that section of the packets to create a new
// HTTPExchange.  The result is a map of httpHdr.RequestURI to HTTPExchange.
// The Data for the HTTPExchange is a slice backed by the same array as d.
//
// For now this is not designed to work well on pipelined responses.
func GetHTTPTraffic(d []*pkt.Packet) map[string]*HTTPExchange {
	var (
		req       string        // The unmodified Request-URI (unique in our case)
		e         *HTTPExchange // tmp for *HTTPExchange while checking err
		httpHdr   *pkt.HttpHdr  // HTTP header - to gather per-packet HTTP data
		ok        bool          // caste success indicator
		err       error         // any error from NewHTTPExchange
		s         int           // start index of an HTTPExchange
		i         int           // index in d - needed for last HTTPExchange
		respIndex int           // index of response header
	)
	m := make(map[string]*HTTPExchange)
	for i = range d {
		if len(d[i].Headers) > ApplicationLayer {
			httpHdr, ok = d[i].Headers[ApplicationLayer].(*pkt.HttpHdr)
			if !ok || httpHdr == nil {
				continue
			}
			if httpHdr.StatusCode == 0 {
				if req != "" {
					// If the next request has the ACK for the
					// last packet of the previous request this
					// will cause that ACK to be missing from
					// the Data in the HTTPExchange.
					e, err = NewHTTPExchange(d[s:i], respIndex-s)
					if err == nil {
						m[req] = e
					}
				}
				s = i
				req = httpHdr.RequestURI
			} else {
				respIndex = i
			}
		}
	}
	e, err = NewHTTPExchange(d[s:i], respIndex-s)
	if err == nil {
		m[req] = e
	}
	return m
}

// String returns the ReqHTTPHdr.RequestURI for use as a non-robust key.
func (e *HTTPExchange) String() string {
	return e.ReqHTTPHdr.RequestURI
}

// GetTCPFlow returns a new *TCPFlow using the packet data in the HTTPExchange.
func (e *HTTPExchange) GetTCPFlow() *TCPFlow {
	return NewTCPFlow(e.Data, e.TCPTuple)
}
