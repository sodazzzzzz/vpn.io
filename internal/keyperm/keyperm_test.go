package keyperm

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not enforced on Windows; Check is a no-op there")
	}
	dir := t.TempDir()
	cases := []struct {
		name      string
		perm      os.FileMode
		wantWarn  bool
		wantWords []string
	}{
		{name: "owner only", perm: 0o600},
		{name: "read only, owner", perm: 0o400},
		{name: "group readable", perm: 0o640, wantWarn: true, wantWords: []string{"group", "0640", "chmod 600"}},
		{name: "world readable", perm: 0o644, wantWarn: true, wantWords: []string{"every user", "0644"}},
		{name: "world writable", perm: 0o666, wantWarn: true, wantWords: []string{"every user"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "-")+".key")
			if err := os.WriteFile(path, []byte("not really a key"), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			// Chmod separately: WriteFile's perm is masked by umask.
			if err := os.Chmod(path, tc.perm); err != nil {
				t.Fatalf("chmod: %v", err)
			}
			got := Check(path)
			if tc.wantWarn && got == "" {
				t.Fatalf("mode %04o produced no warning", tc.perm)
			}
			if !tc.wantWarn && got != "" {
				t.Fatalf("mode %04o produced a warning: %s", tc.perm, got)
			}
			for _, w := range tc.wantWords {
				if !strings.Contains(got, w) {
					t.Errorf("warning %q does not mention %q", got, w)
				}
			}
		})
	}
}

// A missing key is reported by whoever tried to load it, with far more context
// than this package has; warning about it here would just be noise.
func TestCheckIgnoresMissingFile(t *testing.T) {
	if got := Check(filepath.Join(t.TempDir(), "absent.key")); got != "" {
		t.Errorf("Check on a missing file returned %q", got)
	}
}
