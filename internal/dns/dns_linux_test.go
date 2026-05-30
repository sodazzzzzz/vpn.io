//go:build linux

package dns

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildResolvConf(t *testing.T) {
	got := string(buildResolvConf([]string{"1.1.1.1", "9.9.9.9"}))
	for _, want := range []string{"nameserver 1.1.1.1\n", "nameserver 9.9.9.9\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("resolv.conf missing %q\n---\n%s", want, got)
		}
	}
}

// withTempResolvConf points resolvConfPath at a fresh temp path and restores
// the package var afterwards.
func withTempResolvConf(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "resolv.conf")
	orig := resolvConfPath
	resolvConfPath = p
	t.Cleanup(func() { resolvConfPath = orig })
	return p
}

func TestResolvConf_RegularFile_BackupRestore(t *testing.T) {
	p := withTempResolvConf(t)
	const original = "nameserver 192.168.1.1\n"
	if err := os.WriteFile(p, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	r := &linuxRunner{}
	if err := r.applyResolvConf([]string{"1.1.1.1"}); err != nil {
		t.Fatalf("applyResolvConf: %v", err)
	}
	got, _ := os.ReadFile(p)
	if !strings.Contains(string(got), "nameserver 1.1.1.1") {
		t.Fatalf("resolv.conf not rewritten: %q", got)
	}

	if err := r.restoreResolvConf(); err != nil {
		t.Fatalf("restoreResolvConf: %v", err)
	}
	got, _ = os.ReadFile(p)
	if string(got) != original {
		t.Fatalf("restore mismatch: got %q want %q", got, original)
	}
}

func TestResolvConf_Symlink_PreservedAndNotClobbered(t *testing.T) {
	p := withTempResolvConf(t)
	target := filepath.Join(filepath.Dir(p), "stub-resolv.conf")
	const stub = "nameserver 127.0.0.53\n"
	if err := os.WriteFile(target, []byte(stub), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, p); err != nil {
		t.Fatal(err)
	}

	r := &linuxRunner{}
	if err := r.applyResolvConf([]string{"1.1.1.1"}); err != nil {
		t.Fatalf("applyResolvConf: %v", err)
	}
	// Our content must land in a *regular* file, leaving the symlink target
	// (e.g. systemd's stub) untouched.
	if fi, _ := os.Lstat(p); fi.Mode()&os.ModeSymlink != 0 {
		t.Fatal("resolv.conf should be a regular file while applied, not a symlink")
	}
	if stubNow, _ := os.ReadFile(target); string(stubNow) != stub {
		t.Fatalf("symlink target was clobbered: %q", stubNow)
	}

	if err := r.restoreResolvConf(); err != nil {
		t.Fatalf("restoreResolvConf: %v", err)
	}
	fi, err := os.Lstat(p)
	if err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink not restored (err=%v)", err)
	}
	if got, _ := os.Readlink(p); got != target {
		t.Fatalf("symlink target = %q, want %q", got, target)
	}
}

func TestResolvConf_Absent_RemovedOnRestore(t *testing.T) {
	p := withTempResolvConf(t) // path does not exist yet

	r := &linuxRunner{}
	if err := r.applyResolvConf([]string{"1.1.1.1"}); err != nil {
		t.Fatalf("applyResolvConf: %v", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("resolv.conf should have been created: %v", err)
	}

	if err := r.restoreResolvConf(); err != nil {
		t.Fatalf("restoreResolvConf: %v", err)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("resolv.conf should be removed on restore, stat err=%v", err)
	}
}
