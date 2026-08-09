package tunnel

import (
	"bytes"
	"testing"
)

// FuzzReadPacket drives the frame reader plus type dispatch with arbitrary
// bytes — the exact path a peer's traffic takes after TLS. Anything that is not
// a Control or Data frame must come back as an error; nothing here may panic on
// a length that lies, a type byte nobody defined, or an empty frame.
func FuzzReadPacket(f *testing.F) {
	f.Add([]byte{0x00, 0x00})                               // empty frame → ErrEmptyFrame
	f.Add([]byte{0x00, 0x01, byte(FrameData)})              // data frame, no packet
	f.Add([]byte{0x00, 0x01, 0x7f})                         // unknown type
	f.Add([]byte{0x00, 0x03, byte(FrameControl), '{', '}'}) // shortest valid control
	f.Add([]byte{0x00, 0x05, byte(FrameControl), 'n', 'o', 'p', 'e'})

	f.Fuzz(func(t *testing.T, data []byte) {
		typ, body, err := ReadPacket(bytes.NewReader(data))
		if err != nil {
			return
		}
		if typ != FrameControl && typ != FrameData {
			t.Fatalf("ReadPacket returned undeclared frame type 0x%02x", byte(typ))
		}
		if typ != FrameControl {
			return
		}
		// Control bodies are attacker-supplied JSON. Decoding may fail; what it
		// may not do is panic, and a message that decodes must survive the typed
		// parsers, which are what the client and server actually call.
		msg, err := DecodeControl(body)
		if err != nil {
			return
		}
		_, _ = ParseAssignIP(msg)
		_, _ = ParseError(msg)
		_, _ = ParseHello(msg)
	})
}

// FuzzDecodeControl targets the JSON layer on its own, so the fuzzer spends its
// budget on message shapes instead of rediscovering the framing header.
func FuzzDecodeControl(f *testing.F) {
	f.Add([]byte(`{"type":"assign_ip","data":{"ip":"10.8.0.2","netmask":"255.255.255.0"}}`))
	f.Add([]byte(`{"type":"hello","data":{"version":1}}`))
	f.Add([]byte(`{"type":"error","data":{"code":"outdated_client","message":"x"}}`))
	f.Add([]byte(`{"type":"keepalive"}`))
	f.Add([]byte(`{"type":"assign_ip","data":{"ip":"not-an-ip","routes":["nonsense"]}}`))
	f.Add([]byte(`{"type":`))

	f.Fuzz(func(t *testing.T, body []byte) {
		msg, err := DecodeControl(body)
		if err != nil {
			return
		}
		if a, err := ParseAssignIP(msg); err == nil {
			// A parsed assignment is applied to the OS's routing table, so the
			// parser is the only place that can stop a nonsense address.
			if a.IP == "" {
				t.Fatal("ParseAssignIP accepted a message with no IP")
			}
		}
		_, _ = ParseError(msg)
		if h, err := ParseHello(msg); err == nil {
			_ = PeerCompatible(h.Version)
		}
	})
}
