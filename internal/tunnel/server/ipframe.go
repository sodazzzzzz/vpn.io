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

// ErrMalformedIPv4 means the header-length (IHL) or total-length field is
// inconsistent with the bytes actually received. The kernel honours these
// fields when it re-parses the packet, but the router shouldn't forward a buffer
// whose own length fields it hasn't validated.
var ErrMalformedIPv4 = errors.New("malformed IPv4 header/length")

// parseIPv4SrcDst extracts the source and destination IPs from a raw IPv4
// packet. It does not validate the checksum, but it does sanity-check the
// header-length and total-length fields (defense-in-depth) so the router never
// makes a forwarding decision on a packet whose length fields lie about the
// buffer.
func parseIPv4SrcDst(pkt []byte) (src, dst net.IP, err error) {
	if len(pkt) < 20 {
		return nil, nil, ErrShortPacket
	}
	if pkt[0]>>4 != 4 {
		return nil, nil, ErrNotIPv4
	}
	// IHL is the header length in 32-bit words: at least 5 (a 20-byte header)
	// and no larger than the packet. total-length is header+payload and must not
	// claim more bytes than we received (nor fewer than the header).
	ihl := int(pkt[0]&0x0f) * 4
	totalLen := int(pkt[2])<<8 | int(pkt[3])
	if ihl < 20 || ihl > len(pkt) || totalLen < ihl || totalLen > len(pkt) {
		return nil, nil, ErrMalformedIPv4
	}
	src = net.IPv4(pkt[12], pkt[13], pkt[14], pkt[15])
	dst = net.IPv4(pkt[16], pkt[17], pkt[18], pkt[19])
	return src, dst, nil
}
