package frame

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

func TestRoundtrip(t *testing.T) {
	cases := map[string][]byte{
		"empty":  {},
		"small":  []byte("hello"),
		"binary": {0x00, 0x01, 0xff, 0xfe, 0x7f},
		"max":    bytes.Repeat([]byte{0xab}, MaxFrameSize),
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteFrame(&buf, payload); err != nil {
				t.Fatalf("WriteFrame: %v", err)
			}
			got, err := ReadFrame(&buf)
			if err != nil {
				t.Fatalf("ReadFrame: %v", err)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("roundtrip mismatch: got %d bytes, want %d", len(got), len(payload))
			}
			if buf.Len() != 0 {
				t.Fatalf("buffer not drained: %d bytes left", buf.Len())
			}
		})
	}
}

func TestMultipleFrames(t *testing.T) {
	var buf bytes.Buffer
	payloads := [][]byte{[]byte("first"), []byte("second"), {}, []byte("fourth")}
	for _, p := range payloads {
		if err := WriteFrame(&buf, p); err != nil {
			t.Fatalf("WriteFrame: %v", err)
		}
	}
	for i, want := range payloads {
		got, err := ReadFrame(&buf)
		if err != nil {
			t.Fatalf("frame %d: ReadFrame: %v", i, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("frame %d: got %q, want %q", i, got, want)
		}
	}
}

func TestWriteTooLarge(t *testing.T) {
	payload := make([]byte, MaxFrameSize+1)
	err := WriteFrame(io.Discard, payload)
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("got %v, want ErrFrameTooLarge", err)
	}
}

func TestReadCleanEOF(t *testing.T) {
	_, err := ReadFrame(bytes.NewReader(nil))
	if !errors.Is(err, io.EOF) {
		t.Fatalf("got %v, want io.EOF", err)
	}
}

func TestReadTruncatedHeader(t *testing.T) {
	_, err := ReadFrame(bytes.NewReader([]byte{0x00})) // 1 byte of 2
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestReadTruncatedPayload(t *testing.T) {
	// header says 10 bytes, only 3 follow
	data := []byte{0x00, 0x0a, 'a', 'b', 'c'}
	_, err := ReadFrame(bytes.NewReader(data))
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("got %v, want io.ErrUnexpectedEOF", err)
	}
}
