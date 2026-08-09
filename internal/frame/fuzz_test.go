package frame

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

// FuzzReadFrame feeds arbitrary bytes to the framing reader. ReadFrame is the
// first code to touch anything arriving from the network — before TLS has been
// stripped of meaning, before any type dispatch — so it must terminate with an
// error on every input rather than panic, hang, or allocate on a whim.
func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00, 0x00})           // empty payload
	f.Add([]byte{0x00, 0x03, 'a', 'b'}) // header promises more than follows
	f.Add([]byte{0xff, 0xff})           // maximum length, no payload
	f.Add([]byte{0x00, 0x01, 'x', 'y'}) // trailing bytes after a complete frame
	f.Add(append([]byte{0xff, 0xff}, bytes.Repeat([]byte{'z'}, MaxFrameSize)...))

	f.Fuzz(func(t *testing.T, data []byte) {
		payload, err := ReadFrame(bytes.NewReader(data))
		if err != nil {
			return
		}
		// A frame that read cleanly must match its own header, and must never
		// exceed the cap the rest of the code sizes its buffers against.
		if len(payload) > MaxFrameSize {
			t.Fatalf("ReadFrame returned %d bytes, over MaxFrameSize", len(payload))
		}
		if len(data) < 2 {
			t.Fatalf("ReadFrame succeeded on %d bytes of input", len(data))
		}
		if want := int(binary.BigEndian.Uint16(data[:2])); len(payload) != want {
			t.Fatalf("ReadFrame returned %d bytes, header said %d", len(payload), want)
		}
	})
}

// FuzzRoundTrip checks the property the two halves are supposed to have: a
// payload written by WriteFrame reads back byte-identical, and a reader that
// keeps reading sees exactly one frame and then EOF.
func FuzzRoundTrip(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("hello"))
	f.Add(bytes.Repeat([]byte{0}, MaxFrameSize))

	f.Fuzz(func(t *testing.T, payload []byte) {
		var buf bytes.Buffer
		err := WriteFrame(&buf, payload)
		if len(payload) > MaxFrameSize {
			if !errors.Is(err, ErrFrameTooLarge) {
				t.Fatalf("WriteFrame accepted %d bytes: %v", len(payload), err)
			}
			return
		}
		if err != nil {
			t.Fatalf("WriteFrame(%d bytes): %v", len(payload), err)
		}
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("ReadFrame after WriteFrame: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("round trip changed the payload (%d → %d bytes)", len(payload), len(got))
		}
		if _, err := ReadFrame(&buf); !errors.Is(err, io.EOF) {
			t.Fatalf("second ReadFrame = %v, want EOF — one frame in, one frame out", err)
		}
	})
}
