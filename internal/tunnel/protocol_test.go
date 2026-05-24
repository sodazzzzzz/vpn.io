package tunnel

import (
	"bytes"
	"errors"
	"io"
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
	if got != (AssignIP{IP: "10.8.0.2", Gateway: "10.8.0.1", Netmask: "255.255.255.0", MTU: 1380}) {
		t.Fatalf("payload mismatch: %+v", got)
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
