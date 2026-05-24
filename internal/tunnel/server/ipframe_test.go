package server

import (
	"errors"
	"testing"
)

func TestParseIPv4(t *testing.T) {
	// Minimal valid IPv4 header: version=4, IHL=5 → 0x45. src=1.2.3.4, dst=5.6.7.8.
	pkt := []byte{
		0x45, 0x00, 0x00, 0x14, // ver/IHL, ToS, total length
		0x00, 0x00, 0x40, 0x00, // id, flags+frag
		0x40, 0x06, 0x00, 0x00, // TTL, proto=TCP, checksum
		1, 2, 3, 4, // src
		5, 6, 7, 8, // dst
	}
	src, dst, err := parseIPv4SrcDst(pkt)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if src.String() != "1.2.3.4" || dst.String() != "5.6.7.8" {
		t.Fatalf("got src=%s dst=%s", src, dst)
	}
}

func TestParseRejectsShort(t *testing.T) {
	_, _, err := parseIPv4SrcDst([]byte{0x45, 0x00})
	if !errors.Is(err, ErrShortPacket) {
		t.Fatalf("got %v, want ErrShortPacket", err)
	}
}

func TestParseRejectsIPv6(t *testing.T) {
	pkt := make([]byte, 40)
	pkt[0] = 0x60 // version=6
	_, _, err := parseIPv4SrcDst(pkt)
	if !errors.Is(err, ErrNotIPv4) {
		t.Fatalf("got %v, want ErrNotIPv4", err)
	}
}
