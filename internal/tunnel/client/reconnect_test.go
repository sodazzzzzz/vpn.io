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
			Server:           "10.255.255.1:8443", // never dialed: an already-cancelled ctx makes DialContext return context.Canceled before any socket is opened
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

func TestCertErrorClassification_LocalVsRemoteAlert(t *testing.T) {
	// Typed local verify failures → isLocalCertError catches them via errors.As.
	// We don't feed these to isRemoteCertAlert: production never does either
	// (classifyConnectError checks isLocalCertError first), and some x509 error
	// types panic in Error() when built without a Certificate — which is also
	// why the messages use %T, not %v.
	typedLocal := []error{
		x509.UnknownAuthorityError{},
		x509.CertificateInvalidError{Reason: x509.Expired},
		x509.HostnameError{Host: "evil.example.com"},
	}
	for _, err := range typedLocal {
		if !isLocalCertError(err) {
			t.Errorf("isLocalCertError(%T) = false, want true", err)
		}
	}

	// A local verify failure that arrives only as a string is still local, and
	// must not be mistaken for a peer alert.
	localStr := errors.New("tls: failed to verify certificate: x509: certificate signed by unknown authority")
	if !isLocalCertError(localStr) {
		t.Error("isLocalCertError(local string) = false, want true")
	}
	if isRemoteCertAlert(localStr) {
		t.Error("isRemoteCertAlert(local string) = true, want false")
	}

	// Peer alerts: unauthenticated, forgeable — must NOT count as local.
	remote := []error{
		errors.New("remote error: tls: bad certificate"),
		errors.New("remote error: tls: certificate required"),
		errors.New("remote error: tls: unknown certificate authority"),
	}
	for _, err := range remote {
		if isLocalCertError(err) {
			t.Errorf("isLocalCertError(%v) = true, want false (spoofable alert)", err)
		}
		if !isRemoteCertAlert(err) {
			t.Errorf("isRemoteCertAlert(%v) = false, want true", err)
		}
	}

	for _, err := range []error{errors.New("connection refused"), nil} {
		if isLocalCertError(err) || isRemoteCertAlert(err) {
			t.Errorf("%v: classified as a cert error, want neither", err)
		}
	}
}

func TestClassifyConnectError_LocalFatal_AlertSuspected_RestRetryable(t *testing.T) {
	// Local verifier failure → fatal now.
	if got := classifyConnectError(x509.UnknownAuthorityError{}); !errors.Is(got, ErrFatalAuth) {
		t.Errorf("unknown CA: got %v, want ErrFatalAuth", got)
	}
	// Peer alert (forgeable) → suspected, NOT fatal. This is the #124 fix: a
	// single forged "bad certificate" must not tear the tunnel down for good.
	alert := classifyConnectError(errors.New("remote error: tls: bad certificate"))
	if errors.Is(alert, ErrFatalAuth) {
		t.Error("bad-certificate alert wrapped ErrFatalAuth; a single forged alert must not be fatal")
	}
	if !errors.Is(alert, errSuspectedAuth) {
		t.Errorf("bad-certificate alert: got %v, want wrapping errSuspectedAuth", alert)
	}
	// Unrelated → unchanged/retryable.
	if got := classifyConnectError(errors.New("connection refused")); errors.Is(got, ErrFatalAuth) || errors.Is(got, errSuspectedAuth) {
		t.Errorf("connection refused: got %v, want retryable", got)
	}
	if classifyConnectError(nil) != nil {
		t.Error("nil err: want nil")
	}
}

func TestSuspectedAuthExit_GivesUpOnlyAfterLimit(t *testing.T) {
	alert := errSuspectedAuth // errors.Is-matches the wrapped form
	other := errors.New("connection refused")

	// A run of alerts ends the loop exactly at the limit, not before.
	streak := 0
	for i := 1; i < suspectedAuthLimit; i++ {
		var stop bool
		if streak, stop = suspectedAuthExit(alert, streak); stop {
			t.Fatalf("gave up after %d alerts, before the limit of %d", i, suspectedAuthLimit)
		}
	}
	if s, stop := suspectedAuthExit(alert, streak); !stop || s != suspectedAuthLimit {
		t.Fatalf("at the limit: got (streak=%d, stop=%v), want (%d, true)", s, stop, suspectedAuthLimit)
	}

	// A non-alert error resets the streak, so alerts must be *consecutive*.
	streak, _ = suspectedAuthExit(alert, 0)
	if streak != 1 {
		t.Fatalf("one alert: streak = %d, want 1", streak)
	}
	if s, stop := suspectedAuthExit(other, streak); stop || s != 0 {
		t.Fatalf("non-alert must reset: got (streak=%d, stop=%v), want (0, false)", s, stop)
	}
}
