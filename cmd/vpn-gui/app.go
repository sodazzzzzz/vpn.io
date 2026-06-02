package main

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/govpn/internal/control"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// defaultSocket matches cmd/vpn-helper's default control socket. A packaged
// macOS launchd job will set its own path; wire that through when packaging
// lands (the systemd unit already uses /run/vpn-io/helper.sock on Linux).
const defaultSocket = "/var/run/vpn-io-helper.sock"

// socketEnv overrides the control-socket path. It lets a launchd/systemd
// package point the GUI at the path its daemon actually listens on, and lets a
// developer aim the app at a throwaway socket without root.
const socketEnv = "VPN_IO_HELPER_SOCKET"

// helperSocket resolves the control-socket path: the override env var if set,
// otherwise the daemon's default.
func helperSocket() string {
	if s := os.Getenv(socketEnv); s != "" {
		return s
	}
	return defaultSocket
}

// ConnectForm is the non-secret part of a profile the import screen collects:
// the server address and optional knobs. The credential PEMs are picked
// separately (PickCredential) and held in Go, never marshalled through the
// webview.
type ConnectForm struct {
	Server     string `json:"server"`
	ServerName string `json:"serverName"`
	MTU        int    `json:"mtu"`
	TunName    string `json:"tunName"`
}

// CredInfo is what PickCredential reports back to the UI about a picked file:
// which slot it filled and the file's display name. Loaded is false when the
// user cancelled the dialog (slot left unchanged).
type CredInfo struct {
	Role     string `json:"role"`
	FileName string `json:"fileName"`
	Loaded   bool   `json:"loaded"`
}

// CredState tells the import screen whether a credential slot is filled and the
// name of the file that filled it (so a reopened form shows "ca.pem · loaded"
// instead of an empty row). The bytes themselves never cross to the webview.
type CredState struct {
	Loaded   bool   `json:"loaded"`
	FileName string `json:"fileName"`
}

// ProfileInfo is the current import draft summarised for the UI: whether a
// complete profile is staged (so the main screen shows Connect vs. Import),
// the non-secret form fields (to repopulate the form on reopen), and the state
// of each credential slot.
type ProfileInfo struct {
	HasProfile bool      `json:"hasProfile"`
	Server     string    `json:"server"`
	ServerName string    `json:"serverName"`
	MTU        int       `json:"mtu"`
	TunName    string    `json:"tunName"`
	CommonName string    `json:"commonName"`
	CA         CredState `json:"ca"`
	Cert       CredState `json:"cert"`
	Key        CredState `json:"key"`
}

// credential roles, matching the import screen's three file rows.
const (
	roleCA   = "ca"
	roleCert = "cert"
	roleKey  = "key"
)

// App is the Wails-bound backend. It forwards tunnel control to the privileged
// daemon over its socket (via control.Client) and holds the in-progress
// credential draft the import screen builds. The PEM bytes (the private key in
// particular) live only here in memory — they are not sent to the webview and
// are not persisted to disk (persisting a profile across launches is a separate
// step). All draft state is guarded by mu, since Wails may dispatch bound
// methods concurrently.
type App struct {
	ctx context.Context
	cl  *control.Client

	mu       sync.Mutex
	caPEM    []byte
	certPEM  []byte
	keyPEM   []byte
	caName   string // file name of each picked credential, for the form display
	certName string
	keyName  string
	form     ConnectForm
	lastCN   string // CN from the most recent successful validation, for display
}

// NewApp constructs the backend targeting the daemon's control socket.
func NewApp() *App {
	return &App{cl: control.New(helperSocket())}
}

// startup captures the Wails runtime context (needed for the file dialog).
func (a *App) startup(ctx context.Context) { a.ctx = ctx }

// Status reports the daemon's current connection state. The front-end polls
// this; a transport error (typically "daemon not running") comes back as-is.
func (a *App) Status() (control.Status, error) { return a.cl.Status() }

// Disconnect tears the tunnel down (idempotent: a no-op when disconnected).
func (a *App) Disconnect() error { return a.cl.Disconnect() }

// PickCredential opens a native file dialog for one credential slot (ca/cert/
// key), reads the chosen file, sanity-checks that it is PEM, and stores the
// bytes in the draft. The bytes never leave Go. A cancelled dialog returns
// Loaded=false and leaves the slot unchanged.
func (a *App) PickCredential(role string) (CredInfo, error) {
	switch role {
	case roleCA, roleCert, roleKey:
	default:
		return CredInfo{}, fmt.Errorf("unknown credential %q", role)
	}

	path, err := wruntime.OpenFileDialog(a.ctx, wruntime.OpenDialogOptions{
		Title: "Choose " + credLabel(role),
		Filters: []wruntime.FileFilter{
			{DisplayName: "Certificates & keys (*.pem, *.crt, *.cer, *.key)", Pattern: "*.pem;*.crt;*.cer;*.key"},
			{DisplayName: "All files (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil {
		return CredInfo{}, fmt.Errorf("open file dialog: %w", err)
	}
	if path == "" {
		return CredInfo{Role: role, Loaded: false}, nil // cancelled
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return CredInfo{}, fmt.Errorf("read file: %w", err)
	}
	// Light check so an obviously-wrong file is caught here; the real
	// cross-validation (key matches cert, chains to CA, in date) happens in
	// control.Connect via internal/profile when the user connects.
	if block, _ := pem.Decode(data); block == nil {
		return CredInfo{}, fmt.Errorf("%s is not a PEM file", filepath.Base(path))
	}

	name := filepath.Base(path)
	a.mu.Lock()
	switch role {
	case roleCA:
		a.caPEM, a.caName = data, name
	case roleCert:
		a.certPEM, a.certName = data, name
	case roleKey:
		a.keyPEM, a.keyName = data, name
	}
	a.mu.Unlock()

	return CredInfo{Role: role, FileName: name, Loaded: true}, nil
}

// Connect commits the form (server + options) into the draft and brings the
// tunnel up using the staged credentials. It is what the import screen's Save
// calls. Validation errors (bad address, key/cert mismatch, expired, wrong CA)
// come back from control.Connect with a clear message for the form to show.
func (a *App) Connect(form ConnectForm) (control.Connected, error) {
	a.mu.Lock()
	a.form = form
	a.mu.Unlock()
	return a.connect()
}

// Reconnect brings the tunnel up using the already-staged profile — what the
// main screen's Connect / Try again calls once a profile exists.
func (a *App) Reconnect() (control.Connected, error) { return a.connect() }

// connect assembles credentials from the draft and asks the daemon to connect.
func (a *App) connect() (control.Connected, error) {
	a.mu.Lock()
	creds := control.Credentials{
		Server:     a.form.Server,
		ServerName: a.form.ServerName,
		CACertPEM:  a.caPEM,
		CertPEM:    a.certPEM,
		KeyPEM:     a.keyPEM,
		MTU:        a.form.MTU,
		TunName:    a.form.TunName,
	}
	a.mu.Unlock()

	if creds.Server == "" {
		return control.Connected{}, errors.New("enter the server address")
	}
	if len(creds.CACertPEM) == 0 || len(creds.CertPEM) == 0 || len(creds.KeyPEM) == 0 {
		return control.Connected{}, errors.New("choose the CA, client certificate and client key")
	}

	info, err := a.cl.Connect(creds)
	if err != nil {
		return control.Connected{}, err
	}
	a.mu.Lock()
	a.lastCN = info.CommonName
	a.mu.Unlock()
	return info, nil
}

// Profile summarises the staged draft for the UI: HasProfile is true once the
// server and all three credentials are present, which is what flips the main
// screen's primary action from "Import a profile" to "Connect".
func (a *App) Profile() ProfileInfo {
	a.mu.Lock()
	defer a.mu.Unlock()
	return ProfileInfo{
		HasProfile: a.form.Server != "" && len(a.caPEM) > 0 && len(a.certPEM) > 0 && len(a.keyPEM) > 0,
		Server:     a.form.Server,
		ServerName: a.form.ServerName,
		MTU:        a.form.MTU,
		TunName:    a.form.TunName,
		CommonName: a.lastCN,
		CA:         CredState{Loaded: len(a.caPEM) > 0, FileName: a.caName},
		Cert:       CredState{Loaded: len(a.certPEM) > 0, FileName: a.certName},
		Key:        CredState{Loaded: len(a.keyPEM) > 0, FileName: a.keyName},
	}
}

// credLabel is the human label for a credential role, used in the dialog title.
func credLabel(role string) string {
	switch role {
	case roleCA:
		return "CA certificate"
	case roleCert:
		return "client certificate"
	case roleKey:
		return "client key"
	}
	return role
}
