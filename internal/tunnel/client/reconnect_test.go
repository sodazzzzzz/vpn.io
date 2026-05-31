package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestBackoff_StaysWithinBounds(t *testing.T) {
	min := 100 * time.Millisecond
	max := 1 * time.Second

	for attempt := 0; attempt <= 50; attempt++ {
		d := backoff(min, max, attempt)
		if d < min {
			t.Errorf("attempt %d: backoff %v below min %v", attempt, d, min)
		}
		if d > max {
			t.Errorf("attempt %d: backoff %v above max %v", attempt, d, max)
		}
	}
}

func TestBackoff_GrowsThenSaturates(t *testing.T) {
	min := 10 * time.Millisecond
	max := 1 * time.Second

	// At attempt 0, backoff should be in [min, 2*min) — just min + jitter.
	d0 := backoff(min, max, 0)
	if d0 < min || d0 >= 2*min {
		t.Errorf("attempt 0: %v not in [%v, %v)", d0, min, 2*min)
	}

	// By attempt 30+, base saturates at max; result must equal max (no
	// extra jitter would push it above the cap).
	for attempt := 30; attempt < 40; attempt++ {
		d := backoff(min, max, attempt)
		if d != max {
			t.Errorf("attempt %d: %v, want exactly %v after saturation", attempt, d, max)
		}
	}
}

func TestBackoff_NegativeAttemptTreatedAsZero(t *testing.T) {
	min := 10 * time.Millisecond
	max := 1 * time.Second
	d := backoff(min, max, -5)
	if d < min || d >= 2*min {
		t.Errorf("negative attempt: %v not in [%v, %v)", d, min, 2*min)
	}
}

func TestIsFatal_Classifies(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"auth", ErrFatalAuth, true},
		{"server", ErrFatalServer, true},
		{"config", ErrFatalConfig, true},
		// Context cancellation is NOT fatal: the reconnect loop handles
		// shutdown via ctx.Err() before consulting isFatal.
		{"ctx canceled", context.Canceled, false},
		{"ctx deadline", context.DeadlineExceeded, false},
		{"wrapped auth", errors.Join(errors.New("tls"), ErrFatalAuth), true},
		{"random network", errors.New("connection reset by peer"), false},
		{"dial timeout", errors.New("dial tcp 1.2.3.4:8443: i/o timeout"), false},
	}
	for _, tc := range cases {
		if got := isFatal(tc.err); got != tc.want {
			t.Errorf("%s: isFatal(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}

// A signal cancelling ctx mid-dial (DialContext returns context.Canceled)
// must make the reconnect loop exit cleanly (nil), so main() exits 0 rather
// than 1. Guards the ctx.Err()-before-isFatal ordering.
func TestRunReconnectLoop_CleanExitOnCancelDuringDial(t *testing.T) {
	c := &Client{
		cfg: Config{
			Server:           "10.255.255.1:8443", // unroutable; dial aborts on cancel before reaching it
			ReconnectMin:     10 * time.Millisecond,
			ReconnectMax:     10 * time.Millisecond,
			HandshakeTimeout: time.Second,
		},
		log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		tlsConfig: &tls.Config{},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the dial → DialContext returns context.Canceled

	done := make(chan error, 1)
	go func() { done <- c.runReconnectLoop(ctx, make(chan []byte)) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runReconnectLoop returned %v, want nil on ctx-cancel during dial", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("runReconnectLoop did not return after ctx cancellation")
	}
}

func TestIsCertError_DetectsTypedAndStringForms(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"unknown CA (typed)", x509.UnknownAuthorityError{}, true},
		{"invalid cert (typed)", x509.CertificateInvalidError{Reason: x509.Expired}, true},
		{"hostname mismatch (typed)", x509.HostnameError{Host: "evil.example.com"}, true},
		{"bad certificate (alert string)", errors.New("remote error: tls: bad certificate"), true},
		{"unknown CA (alert string)", errors.New("tls: failed to verify certificate: x509: certificate signed by unknown authority"), true},
		{"cert required (alert string)", errors.New("remote error: tls: certificate required"), true},
		{"unrelated", errors.New("connection refused"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		if got := isCertError(tc.err); got != tc.want {
			t.Errorf("%s: isCertError(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}

func TestClassifyConnectError_FatalForCerts_RetryableForRest(t *testing.T) {
	auth := classifyConnectError(x509.UnknownAuthorityError{})
	if !errors.Is(auth, ErrFatalAuth) {
		t.Errorf("unknown CA: got %v, want wrapping ErrFatalAuth", auth)
	}
	net := classifyConnectError(errors.New("connection refused"))
	if errors.Is(net, ErrFatalAuth) {
		t.Errorf("connection refused: got %v, should NOT wrap ErrFatalAuth", net)
	}
	if classifyConnectError(nil) != nil {
		t.Errorf("nil err: want nil")
	}
}
