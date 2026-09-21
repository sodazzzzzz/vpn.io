// Package vless models the node-side state of the VLESS/REALITY service that
// runs next to the vpn.io server: the node's own REALITY parameters, the list
// of clients allowed to use it, the Xray config rendered from both, and the
// vless:// links handed to people.
//
// It deliberately owns no process. Xray-core is the upstream binary that speaks
// the protocol (reimplementing REALITY would mean reproducing a TLS handshake
// byte for byte, and any drift costs both undetectability and compatibility);
// this package only decides what that binary is configured with, so the
// decisions live in Go, under tests, instead of in shell.
//
// The split of state mirrors how it changes: node parameters (keys, the site
// being impersonated) are written once at init and are the thing that must
// never leak, while the client list churns every time someone is added or
// revoked. Keeping them in separate files means the churn never rewrites the
// keys.
package vless

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// DefaultPort is the port the service listens on. REALITY's whole premise is
// looking like the site it impersonates, and that site answers on 443.
const DefaultPort = 443

// DefaultDest and DefaultServerName are the site a fresh node impersonates.
//
// The criteria (docs/VLESS.md repeats them for operators): a third-party site
// that speaks TLS 1.3 and HTTP/2, is reachable and unremarkable from the
// networks our users sit in, stays up, and is not ours — a domain connected to
// us would tie the node back to us the moment anyone looks. This default is a
// reasonable starting point, not a recommendation to keep forever; a node whose
// users all sit behind one ISP may do better with something that ISP sees every
// day.
const (
	DefaultDest       = "www.microsoft.com:443"
	DefaultServerName = "www.microsoft.com"
)

// DefaultFingerprint is the TLS fingerprint clients are told to imitate. It
// travels in the link (the "fp" parameter), because the client — not the node —
// is the side whose ClientHello has to look ordinary.
const DefaultFingerprint = "chrome"

// Flow is the XTLS flow used on a TCP REALITY inbound. Both sides must agree,
// so it is a constant rather than a knob: every client we issue gets it.
const Flow = "xtls-rprx-vision"

// shortIDBytes is the length of a generated shortId. REALITY allows 0..8 bytes;
// 8 is the maximum and costs nothing.
const shortIDBytes = 8

// Node is the REALITY identity of one node: everything a client link is derived
// from, plus the private key that never leaves the machine.
//
// Address is what clients dial. It is kept separate from the certificate-based
// service's address on purpose: the two can move independently, and a node that
// changes its address has to reissue links either way.
type Node struct {
	Address     string   `json:"address"`
	Port        int      `json:"port"`
	Label       string   `json:"label,omitempty"` // what client apps show this node as
	PrivateKey  string   `json:"privateKey"`      // base64url, node-only — never in a link
	PublicKey   string   `json:"publicKey"`       // base64url, travels in every link
	Dest        string   `json:"dest"`            // host:port of the impersonated site
	ServerNames []string `json:"serverNames"`
	Fingerprint string   `json:"fingerprint"`
}

// Client is one person's access to this node.
//
// Name is the same name the certificate-based service uses for that person, so
// one human is one entry in both lists and a revocation can find both. UUID is
// the VLESS credential itself — possession of it is access, which is why a link
// is treated like the .vpnio bundle: private chat only, never a group.
//
// ShortID is per client rather than a node-wide pool: it makes removing someone
// remove their identifier too, instead of leaving it valid for whoever else
// knows it.
type Client struct {
	Name    string `json:"name"`
	UUID    string `json:"uuid"`
	ShortID string `json:"shortId"`
	Created string `json:"created"` // RFC 3339, for "who did I issue this to, when"
}

// NewNode generates a fresh REALITY identity for address. Empty dest,
// serverName or fingerprint take the defaults above.
func NewNode(address, dest, serverName, fingerprint, label string, port int) (Node, error) {
	if strings.TrimSpace(address) == "" {
		return Node{}, fmt.Errorf("vless: node address is required")
	}
	if port == 0 {
		port = DefaultPort
	}
	if dest == "" {
		dest = DefaultDest
	}
	if serverName == "" {
		// Default the SNI to the host being impersonated: announcing a name the
		// dest does not serve is the classic way to build a node that works in
		// testing and stands out in the wild.
		serverName = hostOf(dest)
	}
	if fingerprint == "" {
		fingerprint = DefaultFingerprint
	}
	priv, pub, err := generateKeypair()
	if err != nil {
		return Node{}, err
	}
	n := Node{
		Address:     address,
		Port:        port,
		Label:       label,
		PrivateKey:  priv,
		PublicKey:   pub,
		Dest:        dest,
		ServerNames: []string{serverName},
		Fingerprint: fingerprint,
	}
	if err := n.Validate(); err != nil {
		return Node{}, err
	}
	return n, nil
}

// Validate reports whether the node is usable. It is called on both save and
// load: a hand-edited node.json that is subtly wrong should fail here, with a
// sentence an operator can act on, rather than inside Xray at start-up.
func (n Node) Validate() error {
	switch {
	case strings.TrimSpace(n.Address) == "":
		return fmt.Errorf("vless: node address is empty")
	case n.Port <= 0 || n.Port > 65535:
		return fmt.Errorf("vless: node port %d is out of range", n.Port)
	case n.PrivateKey == "":
		return fmt.Errorf("vless: node has no private key")
	case n.PublicKey == "":
		return fmt.Errorf("vless: node has no public key")
	case len(n.ServerNames) == 0:
		return fmt.Errorf("vless: node has no server names")
	}
	if _, _, err := net.SplitHostPort(n.Dest); err != nil {
		return fmt.Errorf("vless: dest %q must be host:port: %w", n.Dest, err)
	}
	if _, err := decodeKey(n.PrivateKey); err != nil {
		return fmt.Errorf("vless: private key: %w", err)
	}
	if _, err := decodeKey(n.PublicKey); err != nil {
		return fmt.Errorf("vless: public key: %w", err)
	}
	return nil
}

// Endpoint is the address clients dial, as host:port.
func (n Node) Endpoint() string {
	return net.JoinHostPort(n.Address, strconv.Itoa(n.Port))
}

// ServerName is the SNI clients announce: the first configured name.
func (n Node) ServerName() string {
	if len(n.ServerNames) == 0 {
		return ""
	}
	return n.ServerNames[0]
}

// generateKeypair produces an X25519 keypair in the encoding Xray uses:
// base64url without padding, the same shape `xray x25519` prints.
//
// The scalar is clamped before the public key is derived. Every X25519
// implementation clamps internally, so an unclamped scalar would still work —
// but storing the clamped bytes means what we save is exactly what Xray uses,
// and a key compared across tools matches byte for byte.
func generateKeypair() (priv, pub string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("vless: generate key: %w", err)
	}
	clamp(raw)
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", "", fmt.Errorf("vless: derive key: %w", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(raw), enc.EncodeToString(key.PublicKey().Bytes()), nil
}

// clamp applies the RFC 7748 X25519 scalar clamping in place.
func clamp(k []byte) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}

// decodeKey parses a base64url key and checks it is the right size.
func decodeKey(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("not base64url: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("want 32 bytes, got %d", len(b))
	}
	return b, nil
}

// newShortID returns a fresh REALITY shortId as lowercase hex.
func newShortID() (string, error) {
	b := make([]byte, shortIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("vless: generate shortId: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// hostOf returns the host part of a host:port, or the input unchanged when it
// carries no port.
func hostOf(hostPort string) string {
	if h, _, err := net.SplitHostPort(hostPort); err == nil {
		return h
	}
	return hostPort
}
