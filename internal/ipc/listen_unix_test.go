//go:build linux || darwin

package ipc

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestServeOverUnixSocket exercises Listen (peer-credential auth) + Serve
// end to end: the dialer is this same process, so its uid passes the policy.
func TestServeOverUnixSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "h.sock")

	policy := Policy{AllowUID: []uint32{uint32(os.Getuid())}}
	ln, err := Listen(sock, 0600, policy, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	h := &fakeHandler{status: StatusResponse{State: "disconnected"}}
	srv := NewServer(ln, h, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ctx) }()

	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := WriteRequest(conn, Request{Command: CmdStatus}); err != nil {
		t.Fatalf("WriteRequest: %v", err)
	}
	resp, err := ReadResponse(conn)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if !resp.OK {
		t.Fatalf("status failed: %q", resp.Error)
	}

	cancel()
	select {
	case <-served:
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after ctx cancel")
	}
}

// TestListenRejectsUnauthorizedPeer: a policy that admits neither the
// caller's uid nor root-via-uid0 (the test process is not root in CI)
// must cause the connection to be closed before any response.
func TestListenRejectsUnauthorizedPeer(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root: every peer is authorized")
	}
	dir := t.TempDir()
	sock := filepath.Join(dir, "h.sock")

	// Allow only a uid that is not ours.
	policy := Policy{AllowUID: []uint32{uint32(os.Getuid()) + 1}}
	ln, err := Listen(sock, 0600, policy, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	srv := NewServer(ln, &fakeHandler{}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()

	conn, err := net.DialTimeout("unix", sock, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// The listener rejects (closes) the connection; our read should hit EOF
	// rather than a valid response.
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := ReadResponse(conn); err == nil {
		t.Fatal("expected unauthorized peer to be rejected, got a response")
	}
}

// TestListenRefusesWorldWritableDir: if the socket directory is writable by
// others (world-writable without sticky), the stale-socket auto-removal is open
// to TOCTOU, so Listen must refuse rather than silently create the socket.
func TestListenRefusesWorldWritableDir(t *testing.T) {
	// Short path under /tmp: a long t.TempDir() path hits the sun_path limit on
	// macOS, so bind would fail before the directory-permission check runs.
	dir, err := os.MkdirTemp("/tmp", "ipc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	// Defeat umask: set world-write without the sticky bit explicitly.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "s")
	if _, err := Listen(sock, 0600, Policy{}, nil); err == nil {
		t.Fatal("expected Listen to refuse a world-writable socket directory")
	}
}

// TestListenAllowsPrivateDir: a private user directory (0700) must pass the
// directory check and yield a working listener.
func TestListenAllowsPrivateDir(t *testing.T) {
	dir := t.TempDir() // t.TempDir() creates the directory with mode 0700
	sock := filepath.Join(dir, "h.sock")
	ln, err := Listen(sock, 0600, Policy{}, nil)
	if err != nil {
		t.Fatalf("Listen in private dir: %v", err)
	}
	_ = ln.Close()
}

// TestCheckSocketDirSafe covers the directory-check decisions directly: private
// and root-only directories pass, a sticky directory (like /tmp) passes too (the
// kernel won't let a stranger replace someone else's file there), while a group-
// or world-writable directory without sticky is rejected.
func TestCheckSocketDirSafe(t *testing.T) {
	private := t.TempDir() // 0700, owned by us
	if err := checkSocketDirSafe(private); err != nil {
		t.Fatalf("private 0700 dir must be safe: %v", err)
	}

	sticky, err := os.MkdirTemp("/tmp", "ipc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(sticky)
	if err := os.Chmod(sticky, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	if err := checkSocketDirSafe(sticky); err != nil {
		t.Fatalf("world-writable+sticky dir must be safe: %v", err)
	}

	open, err := os.MkdirTemp("/tmp", "ipc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(open)
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := checkSocketDirSafe(open); err == nil {
		t.Fatal("world-writable non-sticky dir must be rejected")
	}

	// Group-writable without sticky is just as exploitable as world-writable and
	// must also be rejected (the docstring promises "writable by no one but the
	// owner").
	group, err := os.MkdirTemp("/tmp", "ipc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(group)
	if err := os.Chmod(group, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := checkSocketDirSafe(group); err == nil {
		t.Fatal("group-writable non-sticky dir must be rejected")
	}
}

func TestListenRefusesNonSocketPath(t *testing.T) {
	dir := t.TempDir()
	reg := filepath.Join(dir, "regular")
	if err := os.WriteFile(reg, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(reg, 0600, Policy{}, nil); err == nil {
		t.Fatal("expected Listen to refuse overwriting a regular file")
	}
}

// TestCheckSocketDirAttrs walks the owner × permission matrix directly. The
// root-owned rows are the reason this helper exists: macOS ships /var/run as
// root:daemon 0775, so a test that has to chown a real directory to root could
// never cover the mode the helper actually runs in.
func TestCheckSocketDirAttrs(t *testing.T) {
	const root, other = 0, 4242
	self := uint32(os.Geteuid())

	cases := []struct {
		name string
		uid  uint32
		mode os.FileMode
		ok   bool
	}{
		{"root 0755", root, 0o755, true},
		// The shape macOS gives /var/run: root-owned and group-writable by a
		// group only root can join.
		{"root 0775", root, 0o775, true},
		{"root 0777", root, 0o777, false},
		{"root 0777 sticky", root, 0o777 | os.ModeSticky, true},
		{"self 0700", self, 0o700, true},
		{"self 0770", self, 0o770, false},
		{"self 0707", self, 0o707, false},
		{"self 0777 sticky", self, 0o777 | os.ModeSticky, true},
		{"foreign owner 0700", other, 0o700, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Running as root collapses the "self" rows onto the root ones, where
			// group-write is deliberately allowed — those rows say nothing then.
			if self == 0 && tc.uid == self && !tc.ok {
				t.Skip("running as root: the self rows duplicate the root ones")
			}
			err := checkSocketDirAttrs("/dir", tc.uid, tc.mode)
			if tc.ok && err != nil {
				t.Fatalf("uid=%d mode=%v must be safe: %v", tc.uid, tc.mode, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("uid=%d mode=%v must be rejected", tc.uid, tc.mode)
			}
		})
	}
}
