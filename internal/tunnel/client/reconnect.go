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

// runReconnectLoop repeats connectOnce with exponential backoff +
// jitter. It exits on ctx cancellation (returns nil) or on the first
// non-retryable error.
func (c *Client) runReconnectLoop(ctx context.Context, outbound <-chan []byte) error {
	attempt := 0
	for {
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

		if held >= reconnectResetAfter {
			attempt = 0
		}

		d := backoff(c.cfg.ReconnectMin, c.cfg.ReconnectMax, attempt)
		c.log.Info("reconnect scheduled", "in", d, "attempt", attempt+1, "err", err)

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

// classifyConnectError maps a connect-path error into either a fatal
// authentication wrapper (so the reconnect loop stops) or the original
// error (so the loop retries). It covers both the tls.Dialer.DialContext
// failure and the first-frame Read that follows a successful dial — TLS
// 1.3 sometimes delays the "bad certificate" alert from the handshake
// until that first Read. Non-cert failures (connection refused, DNS,
// timeout) are returned unchanged and stay retryable.
func classifyConnectError(err error) error {
	if err == nil {
		return nil
	}
	if isCertError(err) {
		return fmt.Errorf("%w: %v", ErrFatalAuth, err)
	}
	return err
}

// isCertError returns true when err is recognizable as a TLS / x509
// certificate verification failure. We check both typed errors (the
// modern path) and string fragments (TLS alerts arrive as generic
// `*net.OpError` with a message).
func isCertError(err error) bool {
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
	return strings.Contains(s, "bad certificate") ||
		strings.Contains(s, "unknown certificate authority") ||
		strings.Contains(s, "certificate signed by unknown authority") ||
		strings.Contains(s, "certificate required") ||
		strings.Contains(s, "tls: failed to verify certificate")
}
