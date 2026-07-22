package tunnel

import (
	"bytes"
	"errors"
	"io"
	"reflect"
	"testing"
)

func TestControlRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	want, err := NewAssignIP(AssignIP{IP: "10.8.0.2", Gateway: "10.8.0.1", Netmask: "255.255.255.0", MTU: 1380})
	if err != nil {
		t.Fatalf("NewAssignIP: %v", err)
	}
	if err := WriteControl(&buf, want); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}

	typ, body, err := ReadPacket(&buf)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if typ != FrameControl {
		t.Fatalf("got type %v, want FrameControl", typ)
	}
	msg, err := DecodeControl(body)
	if err != nil {
		t.Fatalf("DecodeControl: %v", err)
	}
	if msg.Type != CtrlAssignIP {
		t.Fatalf("got %q, want %q", msg.Type, CtrlAssignIP)
	}
	got, err := ParseAssignIP(msg)
	if err != nil {
		t.Fatalf("ParseAssignIP: %v", err)
	}
	if !reflect.DeepEqual(got, AssignIP{IP: "10.8.0.2", Gateway: "10.8.0.1", Netmask: "255.255.255.0", MTU: 1380}) {
		t.Fatalf("payload mismatch: %+v", got)
	}
}

func TestHelloRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	msg, err := NewHello(ProtocolVersion)
	if err != nil {
		t.Fatalf("NewHello: %v", err)
	}
	if err := WriteControl(&buf, msg); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}
	_, body, err := ReadPacket(&buf)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	decoded, err := DecodeControl(body)
	if err != nil {
		t.Fatalf("DecodeControl: %v", err)
	}
	got, err := ParseHello(decoded)
	if err != nil {
		t.Fatalf("ParseHello: %v", err)
	}
	if got.Version != ProtocolVersion {
		t.Fatalf("hello version = %d, want %d", got.Version, ProtocolVersion)
	}
}

// ParseHello rejects a control message that isn't a hello.
func TestParseHelloWrongType(t *testing.T) {
	if _, err := ParseHello(NewKeepalive()); err == nil {
		t.Fatal("ParseHello on a keepalive: want an error")
	}
}

func TestPeerCompatible(t *testing.T) {
	cases := []struct {
		version int
		want    bool
	}{
		{0, true},                  // pre-versioning peer accepted as legacy
		{MinPeerVersion, true},     // exactly the minimum
		{MinPeerVersion + 1, true}, // newer than us is fine (additive)
		{-1, false},                // below the floor (rejected once a future bump raises MinPeerVersion)
	}
	for _, tc := range cases {
		if got := PeerCompatible(tc.version); got != tc.want {
			t.Errorf("PeerCompatible(%d) = %v, want %v", tc.version, got, tc.want)
		}
	}
}

// The server's advertised ProtoVersion survives the wire and is omitted when 0
// (legacy server), keeping older clients wire-compatible.
func TestAssignIPProtoVersion(t *testing.T) {
	msg, err := NewAssignIP(AssignIP{IP: "10.8.0.2", MTU: 1380, ProtoVersion: ProtocolVersion})
	if err != nil {
		t.Fatalf("NewAssignIP: %v", err)
	}
	got, err := ParseAssignIP(msg)
	if err != nil {
		t.Fatalf("ParseAssignIP: %v", err)
	}
	if got.ProtoVersion != ProtocolVersion {
		t.Fatalf("ProtoVersion = %d, want %d", got.ProtoVersion, ProtocolVersion)
	}
	legacy, _ := NewAssignIP(AssignIP{IP: "10.8.0.2", MTU: 1380})
	if bytes.Contains(legacy.Payload, []byte("proto")) {
		t.Errorf("ProtoVersion 0 should be omitted from the wire: %s", legacy.Payload)
	}
}

func TestAssignIPWithRoutesAndDNS(t *testing.T) {
	want := AssignIP{
		IP:      "10.8.0.2",
		Gateway: "10.8.0.1",
		Netmask: "255.255.255.0",
		MTU:     1380,
		Routes:  []string{"0.0.0.0/0", "10.0.0.0/8"},
		DNS:     []string{"1.1.1.1", "9.9.9.9"},
	}
	msg, err := NewAssignIP(want)
	if err != nil {
		t.Fatalf("NewAssignIP: %v", err)
	}

	var buf bytes.Buffer
	if err := WriteControl(&buf, msg); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}
	_, body, err := ReadPacket(&buf)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	decoded, err := DecodeControl(body)
	if err != nil {
		t.Fatalf("DecodeControl: %v", err)
	}
	got, err := ParseAssignIP(decoded)
	if err != nil {
		t.Fatalf("ParseAssignIP: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("roundtrip mismatch:\n  got=%+v\n want=%+v", got, want)
	}
}

// TestAssignIPLegacyWire confirms a payload from an older server (no routes,
// no dns fields) still parses cleanly — the new []string fields land as nil.
func TestAssignIPLegacyWire(t *testing.T) {
	const legacy = `{"type":"assign_ip","payload":{"ip":"10.8.0.5","gateway":"10.8.0.1","netmask":"255.255.255.0","mtu":1380}}`
	msg, err := DecodeControl([]byte(legacy))
	if err != nil {
		t.Fatalf("DecodeControl: %v", err)
	}
	got, err := ParseAssignIP(msg)
	if err != nil {
		t.Fatalf("ParseAssignIP: %v", err)
	}
	if got.Routes != nil || got.DNS != nil {
		t.Fatalf("legacy wire should decode with nil slices, got Routes=%v DNS=%v",
			got.Routes, got.DNS)
	}
	if got.IP != "10.8.0.5" || got.MTU != 1380 {
		t.Fatalf("legacy core fields lost: %+v", got)
	}
}

// TestAssignIPOmitsEmpty verifies routes/dns don't bloat the wire when unused.
func TestAssignIPOmitsEmpty(t *testing.T) {
	msg, err := NewAssignIP(AssignIP{IP: "10.8.0.2", Gateway: "10.8.0.1", Netmask: "255.255.255.0", MTU: 1380})
	if err != nil {
		t.Fatalf("NewAssignIP: %v", err)
	}
	if bytes.Contains(msg.Payload, []byte("routes")) {
		t.Fatalf("empty Routes leaked into wire: %s", msg.Payload)
	}
	if bytes.Contains(msg.Payload, []byte("dns")) {
		t.Fatalf("empty DNS leaked into wire: %s", msg.Payload)
	}
}

func TestDataRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	pkt := []byte{0x45, 0x00, 0x00, 0x1c, 0xde, 0xad} // bogus IPv4-ish header
	if err := WriteData(&buf, pkt); err != nil {
		t.Fatalf("WriteData: %v", err)
	}
	typ, body, err := ReadPacket(&buf)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if typ != FrameData {
		t.Fatalf("got type %v, want FrameData", typ)
	}
	if !bytes.Equal(body, pkt) {
		t.Fatalf("payload mismatch: %x vs %x", body, pkt)
	}
}

func TestKeepaliveRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteControl(&buf, NewKeepalive()); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}
	typ, body, err := ReadPacket(&buf)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if typ != FrameControl {
		t.Fatalf("type=%v", typ)
	}
	msg, err := DecodeControl(body)
	if err != nil {
		t.Fatalf("DecodeControl: %v", err)
	}
	if msg.Type != CtrlKeepalive {
		t.Fatalf("got %q, want keepalive", msg.Type)
	}
	if len(msg.Payload) != 0 {
		t.Fatalf("keepalive should have empty payload, got %s", msg.Payload)
	}
}

func TestErrorRoundtrip(t *testing.T) {
	var buf bytes.Buffer
	msg, err := NewError("no_ip", "address pool exhausted")
	if err != nil {
		t.Fatalf("NewError: %v", err)
	}
	if err := WriteControl(&buf, msg); err != nil {
		t.Fatalf("WriteControl: %v", err)
	}
	_, body, err := ReadPacket(&buf)
	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	decoded, err := DecodeControl(body)
	if err != nil {
		t.Fatalf("DecodeControl: %v", err)
	}
	got, err := ParseError(decoded)
	if err != nil {
		t.Fatalf("ParseError: %v", err)
	}
	if got.Code != "no_ip" || got.Message != "address pool exhausted" {
		t.Fatalf("got %+v", got)
	}
}

func TestUnknownFrameType(t *testing.T) {
	// Build a frame with type byte 0xff by hand: 2-byte length=1, then 0xff.
	raw := []byte{0x00, 0x01, 0xff}
	_, _, err := ReadPacket(bytes.NewReader(raw))
	if !errors.Is(err, ErrUnknownFrameType) {
		t.Fatalf("got %v, want ErrUnknownFrameType", err)
	}
}

func TestEmptyFrame(t *testing.T) {
	// Zero-length frame (header 0x0000 only).
	raw := []byte{0x00, 0x00}
	_, _, err := ReadPacket(bytes.NewReader(raw))
	if !errors.Is(err, ErrEmptyFrame) {
		t.Fatalf("got %v, want ErrEmptyFrame", err)
	}
}

func TestReadPacketCleanEOF(t *testing.T) {
	_, _, err := ReadPacket(bytes.NewReader(nil))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("got %v, want io.EOF", err)
	}
}
