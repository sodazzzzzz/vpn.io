// Package ipc defines the local control protocol between the privileged
// VPN helper daemon and an unprivileged front-end (CLI or GUI).
//
// The daemon runs as root/Administrator and owns the tunnel; the front-end
// runs as the logged-in user and drives it with Connect/Disconnect/Status
// requests over a local transport (a unix socket today; a Windows named
// pipe later). Because that boundary crosses a privilege level, the
// transport authenticates the peer (see Listen) before any request is read.
//
// Wire format: each message is one length-prefixed frame (internal/frame)
// carrying a JSON envelope — a [Request] from the front-end, a [Response]
// from the daemon. One request, one response, then the connection closes.
// JSON (not the tunnel's split control/data channel) is used here because
// this path is low-rate control traffic, not the packet hot path.
package ipc

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/govpn/internal/frame"
)

// Command identifies a request the front-end sends to the daemon.
type Command string

const (
	// CmdConnect brings the tunnel up using the supplied credentials and
	// server address. Payload: [ConnectRequest].
	CmdConnect Command = "connect"
	// CmdDisconnect tears the tunnel down. No payload. Idempotent: a no-op
	// when already disconnected.
	CmdDisconnect Command = "disconnect"
	// CmdStatus reports the current connection state. No payload; the
	// response payload is a [StatusResponse].
	CmdStatus Command = "status"
)

// Request is the JSON envelope the front-end sends. Payload is decoded
// based on Command by the daemon's handler.
type Request struct {
	Command Command         `json:"command"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// Response is the JSON envelope the daemon returns. OK reports whether the
// command succeeded; Error carries a human-readable reason when it did not.
// Payload holds command-specific data (e.g. a StatusResponse).
type Response struct {
	OK      bool            `json:"ok"`
	Error   string          `json:"error,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// ConnectRequest is the payload for CmdConnect. Credentials are carried
// in-memory as PEM bytes (base64-encoded in JSON) rather than as file
// paths, so the daemon never opens a caller-supplied filesystem path as
// root. The combined JSON envelope must fit in a single frame
// (frame.MaxFrameSize, 64 KiB) — ample for a CA + client cert + key.
type ConnectRequest struct {
	Server     string `json:"server"`                // "vpn.example.com:8443"
	ServerName string `json:"server_name,omitempty"` // SNI override; default = host of Server
	CACertPEM  []byte `json:"ca_cert_pem"`           // CA the server is verified against
	CertPEM    []byte `json:"cert_pem"`              // client certificate
	KeyPEM     []byte `json:"key_pem"`               // client private key
	MTU        int    `json:"mtu,omitempty"`         // TUN MTU; 0 = daemon default
	TunName    string `json:"tun_name,omitempty"`    // requested TUN name; empty = driver picks
}

// StatusResponse is the payload returned for CmdStatus. State is one of the
// helper.State values ("disconnected", "connecting", "connected",
// "reconnecting", "failed"). Server is the target of the active or last
// session; SinceUnix is when the current state was entered (Unix seconds,
// 0 if never connected). LastError holds the reason a session failed, if any.
type StatusResponse struct {
	State     string `json:"state"`
	Server    string `json:"server,omitempty"`
	SinceUnix int64  `json:"since_unix,omitempty"`
	LastError string `json:"last_error,omitempty"`
}

// WriteRequest encodes req as a single JSON frame on w.
func WriteRequest(w io.Writer, req Request) error {
	return writeJSON(w, req)
}

// ReadRequest reads a single JSON request frame from r.
func ReadRequest(r io.Reader) (Request, error) {
	var req Request
	return req, readJSON(r, &req)
}

// WriteResponse encodes resp as a single JSON frame on w.
func WriteResponse(w io.Writer, resp Response) error {
	return writeJSON(w, resp)
}

// ReadResponse reads a single JSON response frame from r.
func ReadResponse(r io.Reader) (Response, error) {
	var resp Response
	return resp, readJSON(r, &resp)
}

func writeJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("ipc: marshal: %w", err)
	}
	if len(b) > frame.MaxFrameSize {
		return fmt.Errorf("ipc: message too large (%d > %d bytes)", len(b), frame.MaxFrameSize)
	}
	return frame.WriteFrame(w, b)
}

func readJSON(r io.Reader, v any) error {
	b, err := frame.ReadFrame(r)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("ipc: unmarshal: %w", err)
	}
	return nil
}
