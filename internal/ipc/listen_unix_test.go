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

// TestListenRefusesWorldWritableDir: если каталог сокета доступен на запись
// постороннему (мир-запись без sticky), авто-удаление stale-сокета уязвимо к
// TOCTOU, поэтому Listen обязан отказать, а не создавать сокет молча.
func TestListenRefusesWorldWritableDir(t *testing.T) {
	// Короткий путь под /tmp: длинный путь t.TempDir() на macOS упирается в
	// лимит sun_path, из-за чего bind падает раньше проверки прав каталога.
	dir, err := os.MkdirTemp("/tmp", "ipc")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	// Обходим umask: явно выставляем мир-запись без sticky-бита.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "s")
	if _, err := Listen(sock, 0600, Policy{}, nil); err == nil {
		t.Fatal("expected Listen to refuse a world-writable socket directory")
	}
}

// TestListenAllowsPrivateDir: приватный каталог пользователя (0700) должен
// проходить проверку каталога и давать рабочий листенер.
func TestListenAllowsPrivateDir(t *testing.T) {
	dir := t.TempDir() // t.TempDir() создаёт каталог с режимом 0700
	sock := filepath.Join(dir, "h.sock")
	ln, err := Listen(sock, 0600, Policy{}, nil)
	if err != nil {
		t.Fatalf("Listen in private dir: %v", err)
	}
	_ = ln.Close()
}

// TestCheckSocketDirSafe покрывает решения проверки каталога напрямую:
// приватный и root-only каталоги проходят, sticky-каталог (как /tmp) тоже
// (kernel не даёт постороннему подменить чужой файл), а мир-запись без
// sticky отвергается.
func TestCheckSocketDirSafe(t *testing.T) {
	private := t.TempDir() // 0700, владелец — мы
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
