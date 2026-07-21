package client

import (
	"errors"
	"io"
	"log/slog"
	"testing"
)

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// At full-tunnel, when leak protection can't be established the default is
// fail-closed: leakProtectionUnavailable returns an error (wrapping the cause)
// so the caller refuses the connection rather than coming up while IPv6 leaks.
// With AllowInsecureLeak set it instead warns, marks leakguardOff and returns
// nil so the session proceeds.
func TestLeakProtectionUnavailable(t *testing.T) {
	cause := errors.New("nft: command not found")

	t.Run("fail-closed by default", func(t *testing.T) {
		c := &Client{log: discardLog()}
		err := c.leakProtectionUnavailable("could not enable leak protection", cause)
		if err == nil {
			t.Fatal("want an error (fail-closed), got nil")
		}
		if !errors.Is(err, cause) {
			t.Errorf("error should wrap the cause, got %v", err)
		}
		if c.leakguardOff {
			t.Error("leakguardOff must stay false when we refuse to connect")
		}
	})

	t.Run("opt-in continues", func(t *testing.T) {
		c := &Client{log: discardLog(), cfg: Config{AllowInsecureLeak: true}}
		if err := c.leakProtectionUnavailable("could not enable leak protection", cause); err != nil {
			t.Fatalf("want nil with AllowInsecureLeak, got %v", err)
		}
		if !c.leakguardOff {
			t.Error("leakguardOff should be set after opting into the leak")
		}
	})
}

func TestIsFullTunnel(t *testing.T) {
	tests := []struct {
		name   string
		routes []string
		want   bool
	}{
		{"nil", nil, false},
		{"empty", []string{}, false},
		{"split-only", []string{"10.0.0.0/8", "192.168.0.0/16"}, false},
		{"ipv4 default", []string{"0.0.0.0/0"}, true},
		{"default among specifics", []string{"10.0.0.0/8", "0.0.0.0/0"}, true},
		{"ipv6 default", []string{"::/0"}, true},
		{"bad cidr ignored", []string{"not-a-cidr"}, false},
		{"bad cidr plus default", []string{"nope", "0.0.0.0/0"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isFullTunnel(tt.routes); got != tt.want {
				t.Fatalf("isFullTunnel(%v) = %v, want %v", tt.routes, got, tt.want)
			}
		})
	}
}
