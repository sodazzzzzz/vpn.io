// Package control is the client side of the helper daemon's IPC control
// protocol — the small wrapper a front-end uses to drive the daemon: validate
// credentials, then Connect, Disconnect, and poll Status over the local
// control socket.
//
// It sits one level above internal/ipc. ipc carries the wire envelope; control
// turns it into a typed Status/Connect/Disconnect surface and reuses
// internal/profile to vet credentials locally, so the user gets a clear error
// ("expired", "wrong CA") before a connect attempt rather than an opaque TLS
// failure inside the daemon later. This is the package the desktop GUI binds
// to; the CLI front-end (cmd/vpn-ctl) predates it and inlines the same steps.
package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/govpn/internal/ipc"
	"github.com/govpn/internal/profile"
)

// Client drives one helper daemon over its control socket. The zero value is
// not usable; set Socket (or construct with New).
type Client struct {
	Socket string // path to the daemon's control socket
}

// New returns a Client targeting the daemon listening at socket.
func New(socket string) *Client { return &Client{Socket: socket} }

// Status is the daemon's connection state in front-end-friendly terms. State
// is one of the helper states: "disconnected", "connecting", "connected",
// "reconnecting", "failed". Server is the active or last target; SinceUnix is
// when the state was entered (Unix seconds, 0 if never connected); LastError
// holds the reason a session failed, if any.
type Status struct {
	State     string `json:"state"`
	Server    string `json:"server"`
	SinceUnix int64  `json:"sinceUnix"`
	LastError string `json:"lastError"`
}

// Credentials are the inputs a Connect needs: the three PEM blobs plus the
// server address and optional knobs. A front-end's import step fills these
// from files the user picks; the bytes are passed to the daemon in memory and
// never written back to disk on the way.
type Credentials struct {
	Server     string `json:"server"`               // "vpn.example.com:8443"
	ServerName string `json:"serverName,omitempty"` // SNI / verification host; default = host of Server
	// Endpoints are the other addresses of the SAME node from the profile,
	// tried in order when Server does not answer. Empty means "just Server".
	Endpoints []profile.Endpoint `json:"endpoints,omitempty"`
	// PreferredEndpoint is the address that worked last time, remembered by the
	// front-end. Empty starts at the top of the list.
	PreferredEndpoint string `json:"preferredEndpoint,omitempty"`
	CACertPEM         []byte `json:"caCertPem"`
	CertPEM           []byte `json:"certPem"`
	KeyPEM            []byte `json:"keyPem"`
	MTU               int    `json:"mtu,omitempty"`     // TUN MTU; 0 = daemon default
	TunName           string `json:"tunName,omitempty"` // requested TUN name; empty = driver picks
}

// Connected reports who the validated certificate authenticates as — shown
// after a successful Connect ("connecting as <CN>, certificate expires <...>").
type Connected struct {
	CommonName string    `json:"commonName"`
	NotAfter   time.Time `json:"notAfter"`
}

// Status fetches the daemon's current connection state.
func (c *Client) Status() (Status, error) {
	resp, err := c.do(ipc.Request{Command: ipc.CmdStatus})
	if err != nil {
		return Status{}, err
	}
	var st ipc.StatusResponse
	if err := json.Unmarshal(resp.Payload, &st); err != nil {
		return Status{}, fmt.Errorf("decode status: %w", err)
	}
	return Status{
		State:     st.State,
		Server:    st.Server,
		SinceUnix: st.SinceUnix,
		LastError: st.LastError,
	}, nil
}

// Disconnect tears the tunnel down. It is idempotent: a no-op when already
// disconnected.
func (c *Client) Disconnect() error {
	_, err := c.do(ipc.Request{Command: ipc.CmdDisconnect})
	return err
}

// Connect validates creds locally, then asks the daemon to bring the tunnel
// up. The local check (internal/profile) mirrors what the server enforces at
// mTLS time, surfaced here as a clear message instead of a later handshake
// failure. A negative MTU is rejected as a likely typo — the daemon would
// otherwise coerce it to its default and hide the mistake.
func (c *Client) Connect(creds Credentials) (Connected, error) {
	if creds.MTU < 0 {
		return Connected{}, errors.New("MTU must not be negative")
	}
	endpoints := creds.Endpoints
	if len(endpoints) == 0 {
		endpoints = []profile.Endpoint{{Server: creds.Server, ServerName: creds.ServerName}}
	}
	prof, err := profile.LoadPEMEndpoints(creds.CACertPEM, creds.CertPEM, creds.KeyPEM, endpoints)
	if err != nil {
		return Connected{}, fmt.Errorf("invalid credentials: %w", err)
	}
	ipcEndpoints := make([]ipc.Endpoint, 0, len(prof.Endpoints))
	for _, ep := range prof.Endpoints {
		ipcEndpoints = append(ipcEndpoints, ipc.Endpoint{Server: ep.Server, ServerName: ep.ServerName, Label: ep.Label})
	}
	payload, err := json.Marshal(ipc.ConnectRequest{
		Server:            prof.Server,
		ServerName:        prof.ServerName,
		Endpoints:         ipcEndpoints,
		PreferredEndpoint: creds.PreferredEndpoint,
		CACertPEM:         prof.CACertPEM,
		CertPEM:           prof.CertPEM,
		KeyPEM:            prof.KeyPEM,
		MTU:               creds.MTU,
		TunName:           creds.TunName,
	})
	if err != nil {
		return Connected{}, fmt.Errorf("encode connect request: %w", err)
	}
	if _, err := c.do(ipc.Request{Command: ipc.CmdConnect, Payload: payload}); err != nil {
		return Connected{}, err
	}
	return Connected{CommonName: prof.CommonName, NotAfter: prof.NotAfter}, nil
}

// do sends one request and turns a non-OK daemon response into an error, so
// callers deal only with (value, error). A transport failure (the common case
// being "daemon not running") comes straight back from ipc.Do.
func (c *Client) do(req ipc.Request) (ipc.Response, error) {
	resp, err := ipc.Do(c.Socket, req)
	if err != nil {
		return ipc.Response{}, err
	}
	if !resp.OK {
		if resp.Error == "" {
			return ipc.Response{}, errors.New("daemon reported failure without a reason")
		}
		return ipc.Response{}, errors.New(resp.Error)
	}
	return resp, nil
}
