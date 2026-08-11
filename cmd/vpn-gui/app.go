package main

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"

	"github.com/govpn/internal/control"
	"github.com/govpn/internal/ipc"
	"github.com/govpn/internal/profile"
	"github.com/govpn/internal/profilestore"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// defaultSocket matches cmd/vpn-helper's default control endpoint (a unix
// socket; a named pipe on Windows). A packaged macOS launchd job will set its
// own path; wire that through when packaging lands (the systemd unit already
// uses /run/vpn-io/helper.sock on Linux).
var defaultSocket = ipc.DefaultControlPath()

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

// maxCredentialFileBytes caps how much readCappedFile will read from a chosen
// file. A real CA/cert/key PEM is a few KiB; the cap stops an accidental pick of
// a huge file from blocking the UI goroutine and ballooning memory. It is a
// per-file sanity bound only — deliberately not tied to the IPC frame budget
// (frame.MaxFrameSize, 64 KiB): a profile carries three PEMs base64-encoded in
// one JSON request, so three files near this cap would overflow a single frame.
// Real credentials are far smaller, so the frame is never the binding limit.
const maxCredentialFileBytes = 64 << 10

// readCappedFile reads path but never more than maxCredentialFileBytes. It uses
// an io.LimitReader rather than Stat-then-ReadFile so a file that grows between
// the two calls can't slip past the cap (a self-inflicted TOCTOU), reading one
// byte past the cap so an over-size file is still detected. kind names what the
// file was expected to be, for the error the user sees.
func readCappedFile(path, kind string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxCredentialFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	if len(data) > maxCredentialFileBytes {
		return nil, fmt.Errorf("%s is too large for %s — is this the right file?", filepath.Base(path), kind)
	}
	return data, nil
}

// App is the Wails-bound backend. It forwards tunnel control to the privileged
// daemon over its socket (via control.Client) and holds the credential draft
// the import screen builds. The PEM bytes are never sent to the webview; once a
// profile is imported they are persisted to disk (0600) via profilestore so it
// survives a restart, and reloaded into the draft on launch. All draft state is
// guarded by mu, since Wails may dispatch bound methods concurrently.
type App struct {
	ctx   context.Context
	cl    *control.Client
	tray  *tray
	store *profilestore.Store

	mu       sync.Mutex
	caPEM    []byte
	certPEM  []byte
	keyPEM   []byte
	caName   string // file name of each picked credential, for the form display
	certName string
	keyName  string
	form     ConnectForm
	lastCN   string // CN from the most recent successful validation, for display

	// endpoints is every address the imported profile knows for the node;
	// lastEndpoint is the one that last produced a working session, remembered
	// so the next connect starts where the last one succeeded rather than at
	// the top of the list.
	endpoints    []profile.Endpoint
	lastEndpoint string
}

// NewApp constructs the backend targeting the daemon's control socket and loads
// any previously-saved profile into the draft, so a returning user lands on
// "Connect" rather than "Import a profile".
func NewApp() *App {
	a := &App{cl: control.New(helperSocket())}

	st, err := profilestore.Default()
	if err != nil {
		log.Printf("vpn-gui: profile storage unavailable: %v", err)
		return a
	}
	a.store = st
	switch p, ok, err := st.Load(); {
	case err != nil:
		log.Printf("vpn-gui: could not load saved profile: %v", err)
	case ok:
		a.caPEM, a.certPEM, a.keyPEM = p.CACertPEM, p.CertPEM, p.KeyPEM
		a.caName, a.certName, a.keyName = p.CAName, p.CertName, p.KeyName
		a.form = ConnectForm{Server: p.Server, ServerName: p.ServerName, MTU: p.MTU, TunName: p.TunName}
		a.endpoints, a.lastEndpoint = p.Endpoints, p.LastEndpoint
	}
	return a
}

// startup captures the Wails runtime context (needed for the file dialog and
// window control) and brings up the menu-bar tray.
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	a.tray = newTray(a)
	a.tray.start()
}

// onBeforeClose keeps the app alive in the menu bar when the window is closed:
// it hides the window and cancels the close. Wired to options.OnBeforeClose.
func (a *App) onBeforeClose(context.Context) bool {
	if a.tray != nil {
		return a.tray.onBeforeClose()
	}
	return false
}

// Status reports the daemon's current connection state. The front-end polls
// this; a transport error (typically "daemon not running") comes back as-is.
//
// It is also where the working endpoint is learned: the daemon reports the
// address the live session actually used, which — with a multi-address profile
// — need not be the one we asked for first. Remembering it here means the next
// connect starts at an address known to work instead of timing out on a dead
// one, and the polling loop is the only place the front-end hears about it.
func (a *App) Status() (control.Status, error) {
	st, err := a.cl.Status()
	if err == nil && st.State == "connected" && st.Server != "" {
		a.rememberEndpoint(st.Server)
	}
	return st, err
}

// rememberEndpoint persists server as the last known-good address, if it is one
// this profile actually lists and is not already recorded.
func (a *App) rememberEndpoint(server string) {
	a.mu.Lock()
	if a.lastEndpoint == server || len(a.endpoints) == 0 {
		a.mu.Unlock()
		return
	}
	known := false
	for _, ep := range a.endpoints {
		if ep.Server == server {
			known = true
			break
		}
	}
	if !known {
		a.mu.Unlock()
		return
	}
	a.lastEndpoint = server
	form := a.form
	ca, cert, key := a.caPEM, a.certPEM, a.keyPEM
	caN, certN, keyN := a.caName, a.certName, a.keyName
	a.mu.Unlock()

	a.save(form, ca, cert, key, caN, certN, keyN)
}

// Disconnect tears the tunnel down (idempotent: a no-op when disconnected).
func (a *App) Disconnect() error { return a.cl.Disconnect() }

// reportTrayError surfaces an error from a tray menu action. Tray actions run
// off the menu thread with no window in focus, so a swallowed error left the
// user with no feedback at all — a click on Connect/Disconnect did nothing
// visible when the helper was down or creds were rejected (#136). Log it and
// show a native error dialog. Best-effort: if the dialog can't be shown (no
// window context yet), the log still has it.
func (a *App) reportTrayError(title string, err error) {
	if err == nil {
		return
	}
	log.Printf("vpn-gui: %s: %v", title, err)
	if a.ctx == nil {
		return
	}
	_, _ = wruntime.MessageDialog(a.ctx, wruntime.MessageDialogOptions{
		Type:    wruntime.ErrorDialog,
		Title:   title,
		Message: err.Error(),
	})
}

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

	// A credential PEM is tiny, so a large file is almost certainly the wrong
	// pick — fail early and clearly instead of slurping it.
	data, err := readCappedFile(path, "a certificate or key")
	if err != nil {
		return CredInfo{}, err
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

// ImportProfileBundle opens a native file dialog for a one-file .vpnio profile,
// validates it, and stages it as the current draft (server address + all three
// credentials), persisting it so it survives a restart. The credential bytes
// never cross to the webview. On success it returns the updated ProfileInfo
// (HasProfile=true) so the UI can flip straight to "Connect". A cancelled dialog
// returns a zero ProfileInfo (HasProfile=false) and leaves the draft untouched,
// so the caller can tell "imported" from "cancelled" by HasProfile.
func (a *App) ImportProfileBundle() (ProfileInfo, error) {
	path, err := wruntime.OpenFileDialog(a.ctx, wruntime.OpenDialogOptions{
		Title: "Choose a profile file",
		Filters: []wruntime.FileFilter{
			{DisplayName: "vpn.io profile (*.vpnio)", Pattern: "*.vpnio"},
			{DisplayName: "All files (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil {
		return ProfileInfo{}, fmt.Errorf("open file dialog: %w", err)
	}
	if path == "" {
		return ProfileInfo{}, nil // cancelled — HasProfile=false signals "no import"
	}

	// A profile bundle is a few KiB of JSON; the single-credential cap applies.
	data, err := readCappedFile(path, "a profile")
	if err != nil {
		return ProfileInfo{}, err
	}
	return a.importBundleData(data, filepath.Base(path))
}

// importBundleData validates a .vpnio bundle and stages it as the draft. Split
// out from the dialog so it can be tested without the Wails runtime.
func (a *App) importBundleData(data []byte, sourceName string) (ProfileInfo, error) {
	// ParseBundle runs the full credential validation (key/cert match, chains to
	// the CA, in date, valid server address), so a bad bundle is rejected here
	// rather than later at connect time.
	p, err := profile.ParseBundle(data)
	if err != nil {
		return ProfileInfo{}, fmt.Errorf("invalid profile: %w", err)
	}

	a.mu.Lock()
	a.caPEM, a.certPEM, a.keyPEM = p.CACertPEM, p.CertPEM, p.KeyPEM
	// One file fills all three slots; show its name on each row.
	a.caName, a.certName, a.keyName = sourceName, sourceName, sourceName
	// Keep any advanced knobs (MTU / TUN name) the user already set — the bundle
	// carries the identity and server address, not those — so an import doesn't
	// silently wipe a customised MTU.
	a.form = ConnectForm{Server: p.Server, ServerName: p.ServerName, MTU: a.form.MTU, TunName: a.form.TunName}
	// A re-import replaces the address list, so a remembered endpoint from the
	// previous profile must not survive into it: it may name an address this
	// profile has never heard of.
	a.endpoints, a.lastEndpoint = p.Endpoints, ""
	a.lastCN = p.CommonName
	info := a.profileInfoLocked()
	form := a.form
	ca, cert, key := a.caPEM, a.certPEM, a.keyPEM
	caN, certN, keyN := a.caName, a.certName, a.keyName
	a.mu.Unlock()

	a.save(form, ca, cert, key, caN, certN, keyN)
	return info, nil
}

// Connect commits the form (server + options) into the draft, persists the
// validated profile, and brings the tunnel up. It is what the import screen's
// Save calls. Validation errors (bad address, key/cert mismatch, expired, wrong
// CA) come back with a clear message for the form to show.
//
// The profile is validated and saved before the daemon call, so a usable
// profile survives even if the daemon or server is momentarily unreachable.
func (a *App) Connect(form ConnectForm) (control.Connected, error) {
	if form.MTU < 0 {
		return control.Connected{}, errors.New("MTU must not be negative")
	}

	a.mu.Lock()
	ca, cert, key := a.caPEM, a.certPEM, a.keyPEM
	caN, certN, keyN := a.caName, a.certName, a.keyName
	a.mu.Unlock()

	if _, err := profile.LoadPEM(ca, cert, key, form.Server, form.ServerName); err != nil {
		return control.Connected{}, fmt.Errorf("invalid credentials: %w", err)
	}

	// Commit the form to the draft only after it validates, so a bad address
	// doesn't clobber a previously-working profile.
	a.mu.Lock()
	a.form = form
	a.mu.Unlock()

	a.save(form, ca, cert, key, caN, certN, keyN)

	// Connect with the same snapshot we validated and saved, so a concurrent
	// PickCredential can't slip different bytes to the daemon.
	return a.connect(control.Credentials{
		Server:     form.Server,
		ServerName: form.ServerName,
		CACertPEM:  ca,
		CertPEM:    cert,
		KeyPEM:     key,
		MTU:        form.MTU,
		TunName:    form.TunName,
	})
}

// save persists the staged profile (best-effort). A failure doesn't block the
// connect; it just means the profile won't survive a restart.
func (a *App) save(form ConnectForm, ca, cert, key []byte, caN, certN, keyN string) {
	if a.store == nil {
		return
	}
	a.mu.Lock()
	endpoints, lastEndpoint := a.endpoints, a.lastEndpoint
	a.mu.Unlock()
	err := a.store.Save(profilestore.Profile{
		Server: form.Server, ServerName: form.ServerName, MTU: form.MTU, TunName: form.TunName,
		Endpoints: endpoints, LastEndpoint: lastEndpoint,
		CACertPEM: ca, CertPEM: cert, KeyPEM: key,
		CAName: caN, CertName: certN, KeyName: keyN,
	})
	if err != nil {
		log.Printf("vpn-gui: could not save profile: %v", err)
	}
}

// Reconnect brings the tunnel up using the already-staged profile — what the
// main screen's Connect / Try again calls once a profile exists.
func (a *App) Reconnect() (control.Connected, error) { return a.connect(a.draftCreds()) }

// draftCreds snapshots the staged credentials under the lock.
func (a *App) draftCreds() control.Credentials {
	a.mu.Lock()
	defer a.mu.Unlock()
	return control.Credentials{
		Server:            a.form.Server,
		ServerName:        a.form.ServerName,
		Endpoints:         a.endpoints,
		PreferredEndpoint: a.lastEndpoint,
		CACertPEM:         a.caPEM,
		CertPEM:           a.certPEM,
		KeyPEM:            a.keyPEM,
		MTU:               a.form.MTU,
		TunName:           a.form.TunName,
	}
}

// connect asks the daemon to bring the tunnel up with the given credentials.
// The caller passes a snapshot, so the bytes validated/saved and the bytes sent
// to the daemon are the same set even under concurrent draft changes.
func (a *App) connect(creds control.Credentials) (control.Connected, error) {
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
	return a.profileInfoLocked()
}

// profileInfoLocked builds the draft summary for the UI. The caller must hold
// a.mu — this lets a caller that just mutated the draft under the lock return a
// consistent snapshot without dropping and reacquiring it (and racing a
// concurrent Wails dispatch in the gap).
func (a *App) profileInfoLocked() ProfileInfo {
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
