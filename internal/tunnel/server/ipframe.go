package server

import (
	"errors"
	"net"
)

// ErrNotIPv4 means the packet's first nibble is not 4. We currently only
// handle IPv4 — IPv6 packets are dropped at the boundary.
var ErrNotIPv4 = errors.New("packet is not IPv4")

// ErrShortPacket means the packet is shorter than the minimum IPv4 header.
var ErrShortPacket = errors.New("packet shorter than IPv4 header")

// parseIPv4SrcDst extracts the source and destination IPs from a raw IPv4
// packet. It does not validate the checksum or full header — its job is
// to give the router enough information to make a forwarding decision.
func parseIPv4SrcDst(pkt []byte) (src, dst net.IP, err error) {
	if len(pkt) < 20 {
		return nil, nil, ErrShortPacket
	}
	if pkt[0]>>4 != 4 {
		return nil, nil, ErrNotIPv4
	}
	src = net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15])
	dst = net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
	return src, dst, nil
}
