package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// reconnectResetAfter is how long a single connect attempt must hold
// before we treat the next failure as a "fresh start" and reset the
// backoff counter. Below this, we keep doubling the wait — protects
// against thrashing if the server boots us right after AssignIP.
const reconnectResetAfter = 30 * time.Second

// errSuspectedAuth wraps a certificate-related TLS *alert* received from the
// peer. Unlike a local x509 verification failure, such an alert is
// unauthenticated plaintext that arrives before the handshake completes, so a
// single one can be forged from an on-path or even off-path position. It is
// therefore NOT fatal on its own — the reconnect loop keeps retrying until
// suspectedAuthLimit of them occur in a row, which no longer looks like a
// one-off spoof and more like a genuinely rejected client.
var errSuspectedAuth = errors.New("client: suspected auth failure (unverified TLS alert)")

// suspectedAuthLimit is how many consecutive suspected-auth alerts end the
// loop. One forged packet used to be enough to tear the tunnel down for good.
const suspectedAuthLimit = 5

// runReconnectLoop repeats connectOnce with exponential backoff +
// jitter. It exits on ctx cancellation (returns nil) or on the first
// non-retryable error.
func (c *Client) runReconnectLoop(ctx context.Context, outbound <-chan []byte) error {
	attempt := 0
	suspectedAuth := 0
	for {
		c.emitState(StateConnecting)
		started := time.Now()
		err := c.connectOnce(ctx, outbound)
		held := time.Since(started)

		if err == nil {
			// connectOnce returned cleanly — only happens via ctx cancel.
			return nil
		}

		// A cancelled context means we're shutting down: exit cleanly (nil),
		// whatever error the in-flight attempt surfaced. Checked BEFORE isFatal
		// because DialContext returns context.Canceled when a signal cancels
		// ctx mid-dial, and that must be exit 0, not a non-retryable failure.
		if ctx.Err() != nil {
			return nil
		}

		if isFatal(err) {
			c.log.Error("non-retryable error; client exiting", "err", err)
			return err
		}

		// A cert alert from the peer is retryable (it may be forged), but a run
		// of them is a genuinely rejected client — give up then, not on the first.
		var giveUp bool
		if suspectedAuth, giveUp = suspectedAuthExit(err, suspectedAuth); giveUp {
			c.log.Error("repeated certificate alerts from server; client exiting",
				"streak", suspectedAuth, "err", err)
			return err
		}

		if held >= reconnectResetAfter {
			attempt = 0
		}

		d := backoff(c.cfg.ReconnectMin, c.cfg.ReconnectMax, attempt)
		c.log.Info("reconnect scheduled", "in", d, "attempt", attempt+1, "err", err)

		// Don't report "reconnecting" if a cancel already arrived (e.g. the
		// user disconnected during backoff) — otherwise the controller sees a
		// transient reconnecting→disconnected flip. Mirrors the ctx.Err()
		// guard right after connectOnce above.
		if ctx.Err() != nil {
			return nil
		}
		c.emitState(StateReconnecting)

		select {
		case <-ctx.Done():
			return nil
		case <-time.After(d):
		}
		attempt++
	}
}

// backoff returns the wait before attempt N: min*2^attempt + jitter,
// capped at max. Jitter is uniform in [0, min) to break thundering-herd
// reconnects.
func backoff(minD, maxD time.Duration, attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	// Cap the shift count so min<<attempt can't overflow int64.
	const maxShift = 30
	if attempt > maxShift {
		attempt = maxShift
	}

	base := minD << attempt
	// Detect overflow / above cap; clamp to max.
	if base <= 0 || base > maxD {
		base = maxD
	}

	jitter := time.Duration(0)
	if minD > 0 {
		jitter = time.Duration(rand.Int63n(int64(minD)))
	}
	d := base + jitter
	if d > maxD {
		d = maxD
	}
	return d
}

// isFatal returns true when err must not trigger another reconnect attempt.
//
// Context cancellation is intentionally NOT treated as fatal here: shutdown is
// detected by runReconnectLoop via ctx.Err() (checked before this), so a
// context.Canceled/DeadlineExceeded surfaced by an in-flight dial is a clean
// exit, not a non-retryable failure.
func isFatal(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, ErrFatalAuth) ||
		errors.Is(err, ErrFatalServer) ||
		errors.Is(err, ErrFatalConfig)
}

// classifyConnectError maps a connect-path error into either a fatal wrapper
// (so the reconnect loop stops now), a suspected-auth wrapper (retryable until
// a run of them — see errSuspectedAuth), or the original error (retryable). It
// covers both the tls.Dialer.DialContext failure and the first-frame Read that
// follows a successful dial — TLS 1.3 sometimes delays the alert until that
// first Read. Non-cert failures (connection refused, DNS, timeout) are returned
// unchanged.
func classifyConnectError(err error) error {
	switch {
	case err == nil:
		return nil
	case isLocalCertError(err):
		// Our own x509 verifier rejected the server's cert: locally produced,
		// unspoofable, and unrecoverable without a config change — fatal now.
		return fmt.Errorf("%w: %v", ErrFatalAuth, err)
	case isRemoteCertAlert(err):
		// A cert alert received from the wire. Unauthenticated and forgeable, so
		// not fatal on its own — the loop tolerates a few (see errSuspectedAuth).
		return fmt.Errorf("%w: %v", errSuspectedAuth, err)
	default:
		return err
	}
}

// isLocalCertError reports whether err was produced by OUR x509 verifier
// rejecting the server's certificate — as a typed error (the modern path) or,
// as a fallback when the type is lost through wrapping, by the message our
// verifier emits. Locally generated, so it can't be spoofed and is genuinely
// non-retryable.
func isLocalCertError(err error) bool {
	if err == nil {
		return false
	}
	var cvErr *tls.CertificateVerificationError
	if errors.As(err, &cvErr) {
		return true
	}
	var uaErr x509.UnknownAuthorityError
	if errors.As(err, &uaErr) {
		return true
	}
	var ciErr x509.CertificateInvalidError
	if errors.As(err, &ciErr) {
		return true
	}
	var heErr x509.HostnameError
	if errors.As(err, &heErr) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "certificate signed by unknown authority") ||
		strings.Contains(s, "tls: failed to verify certificate")
}

// isRemoteCertAlert reports whether err is a certificate-related TLS *alert*
// received from the peer. These surface only as a message ("remote error: tls:
// ..."), never as a typed local error, and are unauthenticated — hence treated
// as suspected rather than fatal (#124).
func isRemoteCertAlert(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "bad certificate") ||
		strings.Contains(s, "unknown certificate authority") ||
		strings.Contains(s, "certificate required")
}

// suspectedAuthExit tracks a run of unverified cert alerts. Because one such
// alert can be forged from an unauthenticated position, a single (or a few)
// must not end the loop — only suspectedAuthLimit in a row do. Any other error
// resets the streak to zero.
func suspectedAuthExit(err error, streak int) (newStreak int, stop bool) {
	if !errors.Is(err, errSuspectedAuth) {
		return 0, false
	}
	streak++
	return streak, streak >= suspectedAuthLimit
}
