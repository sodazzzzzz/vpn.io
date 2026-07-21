//go:build unix

package execx

import (
	"strings"
	"testing"
	"time"
)

// A command that outlives the timeout is killed and reported as a timeout — the
// whole point of the package (#147).
func TestRun_TimesOut(t *testing.T) {
	start := time.Now()
	_, err := run(100*time.Millisecond, nil, "sleep", "10")
	if err == nil {
		t.Fatal("want a timeout error for a command that outlives the timeout")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error = %q, want it to mention a timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("run took %v; the timeout should have killed it near 100ms", elapsed)
	}
}

func TestRun_SuccessAndFailure(t *testing.T) {
	if err := Run("true"); err != nil {
		t.Errorf("Run(true): %v", err)
	}
	if err := Run("false"); err == nil {
		t.Error("Run(false): want an error")
	}
	out, err := Output("echo", "hello")
	if err != nil {
		t.Fatalf("Output(echo): %v", err)
	}
	if strings.TrimSpace(string(out)) != "hello" {
		t.Errorf("Output = %q, want hello", out)
	}
}

func TestRunStdin_FeedsStdin(t *testing.T) {
	// `cat` echoes stdin back; Run's success path discards it, so just assert no
	// error — the command reads our stdin and exits 0.
	if err := RunStdin([]byte("hi"), "cat"); err != nil {
		t.Errorf("RunStdin(cat): %v", err)
	}
}
