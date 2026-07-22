// Package tunnel defines the wire protocol shared by the VPN server and client.
//
// Each frame carried by [frame.WriteFrame]/[frame.ReadFrame] has a 1-byte
// type prefix:
//
//	0x01  Control  — JSON-encoded control message (see ControlMessage)
//	0x02  Data     — raw IP packet from/for the TUN interface
//
// Splitting the channel by type byte (instead of wrapping data in JSON)
// keeps the hot path — IP packets — zero-copy and free of parsing overhead.
package tunnel

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/govpn/internal/frame"
)

// FrameType is the 1-byte tag that prefixes every frame payload.
type FrameType byte

const (
	FrameControl FrameType = 0x01
	FrameData    FrameType = 0x02
)

// ProtocolVersion is the wire-protocol version this build speaks. Bump it ONLY
// for a breaking change; additive changes — new omitempty fields, new control
// types (both sides ignore ones they don't recognize) — keep the same version.
//
// MinPeerVersion is the oldest peer version this build still interoperates with.
// Raise it in lockstep with a breaking ProtocolVersion bump so the newer side
// can reject a peer too old to understand the change with a clear message,
// instead of failing opaquely mid-session (#143). Peers that predate versioning
// advertise 0 and are treated as legacy — accepted, since they can't be told
// apart from a silent-old client anyway.
const (
	ProtocolVersion = 1
	MinPeerVersion  = 1
)

// PeerCompatible reports whether a peer advertising peerVersion is one we can
// talk to. 0 means "pre-versioning" (legacy) and is accepted; anything else must
// be at least MinPeerVersion.
func PeerCompatible(peerVersion int) bool {
	return peerVersion == 0 || peerVersion >= MinPeerVersion
}

// ControlType identifies a control message inside a Control frame.
type ControlType string

const (
	CtrlAssignIP  ControlType = "assign_ip"
	CtrlKeepalive ControlType = "keepalive"
	CtrlError     ControlType = "error"
	// CtrlHello is the client's first control frame, announcing its
	// ProtocolVersion so the server can reject a client too old for a breaking
	// change. Older clients don't send it; the server reads a missing Hello as
	// the legacy version.
	CtrlHello ControlType = "hello"
)

// ControlMessage is the JSON envelope for every control frame.
//
// Payload is decoded based on Type by [DecodeControl]. Producers should use
// the typed helpers ([NewAssignIP], [NewKeepalive], [NewError]) instead of
// constructing this struct directly.
type ControlMessage struct {
	Type    ControlType     `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

// AssignIP is sent server→client after the TLS+mTLS handshake to tell the
// client which tunnel IP it owns and how to configure its TUN interface.
//
// Routes and DNS are optional pushes. Routes are CIDR prefixes the client
// should install via the TUN device (e.g. "0.0.0.0/0" for a full-tunnel
// setup). DNS holds resolver addresses to configure on the client. Both
// are JSON-omitted when empty so older clients/servers stay wire-compatible.
type AssignIP struct {
	IP      string   `json:"ip"`               // e.g. "10.8.0.2"
	Gateway string   `json:"gateway"`          // e.g. "10.8.0.1"
	Netmask string   `json:"netmask"`          // e.g. "255.255.255.0"
	MTU     int      `json:"mtu"`              // e.g. 1380
	Routes  []string `json:"routes,omitempty"` // CIDRs, e.g. ["0.0.0.0/0"]
	DNS     []string `json:"dns,omitempty"`    // resolver IPs, e.g. ["1.1.1.1"]

	// ProtoVersion is the server's ProtocolVersion, so the client can spot a
	// server too old for it and fail with a clear message rather than mid-session
	// (#143). Omitted (0) by pre-versioning servers.
	ProtoVersion int `json:"proto,omitempty"`

	// KeepaliveSecs is the server's keepalive interval in seconds. The client
	// bases its read-idle deadline on this — the server is the pulse source — so
	// the deadline can't be tripped by an interval mismatch between the two
	// sides' configs (#179). Omitted (0) by older servers; the client then falls
	// back to its own interval, preserving wire compatibility.
	KeepaliveSecs int `json:"keepalive_secs,omitempty"`
}

// ErrorMsg is sent server→client (or vice versa) to report a fatal protocol
// error before the connection is closed.
type ErrorMsg struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// ErrUnknownFrameType is returned by ReadPacket when the type byte is not
// a recognized FrameType.
var ErrUnknownFrameType = errors.New("tunnel: unknown frame type")

// ErrEmptyFrame is returned when a frame arrives with no type byte at all.
var ErrEmptyFrame = errors.New("tunnel: empty frame")

// WriteControl JSON-encodes msg and sends it as a Control frame.
func WriteControl(w io.Writer, msg ControlMessage) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("tunnel: marshal control: %w", err)
	}
	buf := make([]byte, 1+len(body))
	buf[0] = byte(FrameControl)
	copy(buf[1:], body)
	return frame.WriteFrame(w, buf)
}

// WriteData sends a raw IP packet as a Data frame.
//
// pkt is copied into the frame buffer, so callers may reuse pkt immediately.
func WriteData(w io.Writer, pkt []byte) error {
	buf := make([]byte, 1+len(pkt))
	buf[0] = byte(FrameData)
	copy(buf[1:], pkt)
	return frame.WriteFrame(w, buf)
}

// ReadPacket reads the next frame and returns its type plus body (the bytes
// after the 1-byte type prefix).
//
// For FrameControl, body is the raw JSON — pass it to [DecodeControl] to
// get a typed ControlMessage. For FrameData, body is the IP packet.
func ReadPacket(r io.Reader) (FrameType, []byte, error) {
	payload, err := frame.ReadFrame(r)
	if err != nil {
		return 0, nil, err
	}
	if len(payload) == 0 {
		return 0, nil, ErrEmptyFrame
	}
	t := FrameType(payload[0])
	switch t {
	case FrameControl, FrameData:
		return t, payload[1:], nil
	default:
		return 0, nil, fmt.Errorf("%w: 0x%02x", ErrUnknownFrameType, payload[0])
	}
}

// DecodeControl parses the JSON body of a Control frame into a ControlMessage.
func DecodeControl(body []byte) (ControlMessage, error) {
	var msg ControlMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return ControlMessage{}, fmt.Errorf("tunnel: unmarshal control: %w", err)
	}
	return msg, nil
}

// NewAssignIP builds an AssignIP control message.
func NewAssignIP(a AssignIP) (ControlMessage, error) {
	raw, err := json.Marshal(a)
	if err != nil {
		return ControlMessage{}, fmt.Errorf("tunnel: marshal assign_ip: %w", err)
	}
	return ControlMessage{Type: CtrlAssignIP, Payload: raw}, nil
}

// NewKeepalive builds an empty keepalive control message.
func NewKeepalive() ControlMessage {
	return ControlMessage{Type: CtrlKeepalive}
}

// Hello is the payload for CtrlHello: the client's advertised ProtocolVersion.
type Hello struct {
	Version int `json:"version"`
}

// NewHello builds a hello control message carrying version.
func NewHello(version int) (ControlMessage, error) {
	raw, err := json.Marshal(Hello{Version: version})
	if err != nil {
		return ControlMessage{}, fmt.Errorf("tunnel: marshal hello: %w", err)
	}
	return ControlMessage{Type: CtrlHello, Payload: raw}, nil
}

// ParseHello decodes a CtrlHello control message's payload.
func ParseHello(msg ControlMessage) (Hello, error) {
	if msg.Type != CtrlHello {
		return Hello{}, fmt.Errorf("tunnel: not a hello message (type %q)", msg.Type)
	}
	var h Hello
	if err := json.Unmarshal(msg.Payload, &h); err != nil {
		return Hello{}, fmt.Errorf("tunnel: unmarshal hello: %w", err)
	}
	return h, nil
}

// NewError builds an error control message.
func NewError(code, message string) (ControlMessage, error) {
	raw, err := json.Marshal(ErrorMsg{Code: code, Message: message})
	if err != nil {
		return ControlMessage{}, fmt.Errorf("tunnel: marshal error: %w", err)
	}
	return ControlMessage{Type: CtrlError, Payload: raw}, nil
}

// ParseAssignIP extracts an AssignIP payload from a decoded ControlMessage.
func ParseAssignIP(msg ControlMessage) (AssignIP, error) {
	if msg.Type != CtrlAssignIP {
		return AssignIP{}, fmt.Errorf("tunnel: expected %q, got %q", CtrlAssignIP, msg.Type)
	}
	var a AssignIP
	if err := json.Unmarshal(msg.Payload, &a); err != nil {
		return AssignIP{}, fmt.Errorf("tunnel: unmarshal assign_ip: %w", err)
	}
	return a, nil
}

// ParseError extracts an ErrorMsg payload from a decoded ControlMessage.
func ParseError(msg ControlMessage) (ErrorMsg, error) {
	if msg.Type != CtrlError {
		return ErrorMsg{}, fmt.Errorf("tunnel: expected %q, got %q", CtrlError, msg.Type)
	}
	var e ErrorMsg
	if err := json.Unmarshal(msg.Payload, &e); err != nil {
		return ErrorMsg{}, fmt.Errorf("tunnel: unmarshal error: %w", err)
	}
	return e, nil
}
