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

// A valid 20-byte base, corrupted one length field at a time (#157).
func TestParseRejectsMalformedLengths(t *testing.T) {
	base := func() []byte {
		return []byte{
			0x45, 0x00, 0x00, 0x14, // ver/IHL=5, ToS, total-length=20
			0x00, 0x00, 0x40, 0x00,
			0x40, 0x06, 0x00, 0x00,
			1, 2, 3, 4,
			5, 6, 7, 8,
		}
	}
	cases := []struct {
		name    string
		corrupt func([]byte)
	}{
		// total-length 60 > buffer 20
		{"total-length claims more than the buffer", func(p []byte) { p[2], p[3] = 0x00, 0x3c }},
		// total-length 10 < header 20
		{"total-length smaller than the header", func(p []byte) { p[2], p[3] = 0x00, 0x0a }},
		// IHL=4 → 16-byte header, below the minimum
		{"IHL below the minimum", func(p []byte) { p[0] = 0x44 }},
		// IHL=15 → 60-byte header, larger than the buffer
		{"IHL larger than the buffer", func(p []byte) { p[0] = 0x4f }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pkt := base()
			tc.corrupt(pkt)
			if _, _, err := parseIPv4SrcDst(pkt); !errors.Is(err, ErrMalformedIPv4) {
				t.Fatalf("got %v, want ErrMalformedIPv4", err)
			}
		})
	}
}

// total-length SHORTER than the buffer (trailing padding) is allowed: the kernel
// honours total-length, so extra bytes are harmless. We only reject fields that
// lie about the buffer being longer than it is.
func TestParseAllowsTrailingPadding(t *testing.T) {
	pkt := []byte{
		0x45, 0x00, 0x00, 0x14, // total-length 20
		0x00, 0x00, 0x40, 0x00,
		0x40, 0x06, 0x00, 0x00,
		1, 2, 3, 4,
		5, 6, 7, 8,
		0xde, 0xad, 0xbe, 0xef, // trailing padding: len=24, total-length=20
	}
	if _, _, err := parseIPv4SrcDst(pkt); err != nil {
		t.Fatalf("trailing padding rejected: %v", err)
	}
}
