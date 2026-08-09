package ipc

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/govpn/internal/frame"
)

// The control socket is local, but "local" is not "trusted": on a shared or
// multi-user machine any process the ACL lets through can write whatever it
// likes into it, and the daemon on the other end runs as root. These tests
// cover what that side must survive — garbage, truncation, oversized and
// half-open connections — and, above all, that it keeps serving afterwards.

// countingHandler records whether the server ever dispatched a command, so a
// test can assert that malformed input never reached the tunnel controller.
type countingHandler struct {
	connects    atomic.Int32
	disconnects atomic.Int32
	statuses    atomic.Int32
}

func (h *countingHandler) Connect(ConnectRequest) error { h.connects.Add(1); return nil }
func (h *countingHandler) Disconnect() error            { h.disconnects.Add(1); return nil }
func (h *countingHandler) Status() StatusResponse {
	h.statuses.Add(1)
	return StatusResponse{State: "disconnected"}
}

// startTestServer runs a Server on a loopback TCP listener — the transport is
// irrelevant to these cases, and TCP keeps them running on every platform.
func startTestServer(t *testing.T) (addr string, h *countingHandler) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	h = &countingHandler{}
	srv := NewServer(ln, h, nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-done
		_ = ln.Close()
	})
	return ln.Addr().String(), h
}

func dial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	return conn
}

// goodRequest sends a Status request and requires a well-formed response — the
// probe every malformed case ends with, to prove the server is still alive.
func goodRequest(t *testing.T, addr string) Response {
	t.Helper()
	conn := dial(t, addr)
	if err := WriteRequest(conn, Request{Command: CmdStatus, Version: IPCVersion}); err != nil {
		t.Fatalf("write status request: %v", err)
	}
	resp, err := ReadResponse(conn)
	if err != nil {
		t.Fatalf("read status response: %v", err)
	}
	return resp
}

func TestServerSurvivesMalformedInput(t *testing.T) {
	// Each case is written raw onto the socket, bypassing WriteRequest — that is
	// the point: a hostile client does not use our encoder.
	cases := []struct {
		name  string
		write func(net.Conn)
	}{
		{
			name:  "connect and close immediately",
			write: func(c net.Conn) { _ = c.Close() },
		},
		{
			name:  "random bytes",
			write: func(c net.Conn) { _, _ = c.Write([]byte("GET / HTTP/1.1\r\n\r\n")) },
		},
		{
			name: "header only, then close",
			write: func(c net.Conn) {
				_, _ = c.Write([]byte{0xff, 0xff})
				_ = c.Close()
			},
		},
		{
			name: "length header lies about a huge payload",
			write: func(c net.Conn) {
				var hdr [2]byte
				binary.BigEndian.PutUint16(hdr[:], frame.MaxFrameSize)
				_, _ = c.Write(hdr[:])
				_, _ = c.Write([]byte("only a few bytes"))
				_ = c.Close()
			},
		},
		{
			name: "truncated mid-frame",
			write: func(c net.Conn) {
				body, _ := json.Marshal(Request{Command: CmdConnect, Version: IPCVersion})
				var hdr [2]byte
				binary.BigEndian.PutUint16(hdr[:], uint16(len(body)))
				_, _ = c.Write(hdr[:])
				_, _ = c.Write(body[:len(body)/2])
				_ = c.Close()
			},
		},
		{
			name:  "empty frame",
			write: func(c net.Conn) { _, _ = c.Write([]byte{0x00, 0x00}) },
		},
		{
			name:  "valid frame, invalid JSON",
			write: func(c net.Conn) { _ = frame.WriteFrame(c, []byte("{not json")) },
		},
		{
			name:  "JSON that is not an object",
			write: func(c net.Conn) { _ = frame.WriteFrame(c, []byte(`["connect"]`)) },
		},
		{
			name: "unknown command",
			write: func(c net.Conn) {
				body, _ := json.Marshal(Request{Command: "rm -rf", Version: IPCVersion})
				_ = frame.WriteFrame(c, body)
			},
		},
		{
			name: "connect with a payload that is not a ConnectRequest",
			write: func(c net.Conn) {
				body, _ := json.Marshal(Request{
					Command: CmdConnect, Version: IPCVersion,
					Payload: json.RawMessage(`"just a string"`),
				})
				_ = frame.WriteFrame(c, body)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			addr, h := startTestServer(t)
			tc.write(dial(t, addr))

			// The server must still answer a well-formed request afterwards.
			resp := goodRequest(t, addr)
			if !resp.OK {
				t.Fatalf("status after malformed input failed: %s", resp.Error)
			}
			// Nothing malformed may reach the tunnel: the only handler call in
			// this test is the Status probe above.
			if got := h.connects.Load(); got != 0 {
				t.Errorf("Connect was dispatched %d time(s) for malformed input", got)
			}
			if got := h.disconnects.Load(); got != 0 {
				t.Errorf("Disconnect was dispatched %d time(s) for malformed input", got)
			}
		})
	}
}

// A wedge of half-open connections must not stop the daemon from serving. This
// is the shape of an accidental denial of service — a crashing front-end
// reconnecting in a loop — more than a deliberate one.
func TestServerSurvivesManyAbandonedConnections(t *testing.T) {
	addr, _ := startTestServer(t)
	for range 64 {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		_, _ = conn.Write([]byte{0x00})
		_ = conn.Close()
	}
	if resp := goodRequest(t, addr); !resp.OK {
		t.Fatalf("status after 64 abandoned connections failed: %s", resp.Error)
	}
}

// The envelope must fit one frame. The encoder is the boundary that enforces
// it: without this check an oversized ConnectRequest would be written as a
// truncated frame and read on the far side as corruption.
func TestWriteRequestRejectsOversizedEnvelope(t *testing.T) {
	payload, err := json.Marshal(ConnectRequest{
		Server:    "vpn.example.com:8443",
		CACertPEM: bytes.Repeat([]byte("A"), frame.MaxFrameSize),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var buf bytes.Buffer
	err = WriteRequest(&buf, Request{Command: CmdConnect, Payload: payload, Version: IPCVersion})
	if err == nil {
		t.Fatal("WriteRequest accepted an envelope larger than one frame")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Errorf("error does not explain the size limit: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("WriteRequest wrote %d bytes before refusing", buf.Len())
	}
}

// Reading is bounded by the same limit from the other direction: a frame can
// never exceed MaxFrameSize, so a response claiming more is a protocol error
// rather than an allocation the daemon performs on request.
func TestReadResponseBoundedByFrameSize(t *testing.T) {
	var buf bytes.Buffer
	huge := bytes.Repeat([]byte("B"), frame.MaxFrameSize+1)
	if err := frame.WriteFrame(&buf, huge); err == nil {
		t.Fatal("frame.WriteFrame accepted an oversized payload")
	}
	if _, err := ReadResponse(&buf); err == nil {
		t.Fatal("ReadResponse succeeded on an empty buffer")
	}
}
