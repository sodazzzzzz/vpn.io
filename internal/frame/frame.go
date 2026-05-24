// Package frame implements length-prefixed framing over a byte stream.
//
// Each frame is encoded as a 2-byte big-endian length header followed by
// exactly that many payload bytes. The maximum payload size is 65535 bytes
// (MaxFrameSize), which matches the uint16 length field.
//
// TLS gives us a reliable byte stream with no message boundaries, so we
// need explicit framing to know where one logical message ends and the
// next begins.
package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MaxFrameSize is the largest payload a single frame can carry.
const MaxFrameSize = 65535

// ErrFrameTooLarge is returned by WriteFrame when payload exceeds MaxFrameSize.
var ErrFrameTooLarge = errors.New("frame: payload exceeds MaxFrameSize")

// WriteFrame writes a length-prefixed frame to w.
//
// It performs a single Write of the header followed by a single Write of
// the payload. Callers that share w across goroutines must serialize their
// own writes (e.g. with a mutex) — this function does not.
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) > MaxFrameSize {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, len(payload))
	}
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("frame: write header: %w", err)
	}
	if len(payload) == 0 {
		return nil
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("frame: write payload: %w", err)
	}
	return nil
}

// ReadFrame reads one length-prefixed frame from r and returns its payload.
//
// On a clean EOF before any bytes are read, io.EOF is returned unchanged so
// callers can detect a graceful close. EOF mid-frame is reported as
// io.ErrUnexpectedEOF (via io.ReadFull).
//
// The returned slice is freshly allocated and owned by the caller.
func ReadFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		// io.ReadFull turns EOF-after-zero-bytes into io.EOF and
		// EOF-after-some-bytes into io.ErrUnexpectedEOF — exactly what we want.
		return nil, err
	}
	n := binary.BigEndian.Uint16(hdr[:])
	if n == 0 {
		return []byte{}, nil
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("frame: read payload (%d bytes): %w", n, err)
	}
	return payload, nil
}
