// Package firewall installs OS-level leak-protection rules while a
// full-tunnel session is up and removes them when it goes down.
//
// Right now it does exactly one thing: block routable IPv6 egress. The
// data plane is IPv4-only (the server drops IPv6 at the TUN boundary), so
// when the client redirects the IPv4 default through the tunnel the host's
// untouched IPv6 default would carry traffic straight out the open network
// — a real address leak. Dropping global-unicast IPv6 makes dual-stack
// apps fall back to IPv4 (Happy Eyeballs, RFC 8305), which does go through
// the tunnel.
//
// We block 2000::/3 — all currently-allocated global unicast IPv6 — and
// deliberately leave loopback (::1), link-local (fe80::/10) and ULA
// (fc00::/7) alone so NDP, mDNS and local IPv6 keep working.
//
// The Manager type is the cross-platform façade with a single
// BlockIPv6→Remove lifecycle (mirroring internal/dns and internal/route);
// per-OS files supply a Runner via newRunner(). This package is also the
// intended home for the session kill-switch (blocking IPv4 leaks when the
// tunnel drops), which will extend the Runner rather than start over.
package firewall

import (
	"fmt"
	"log/slog"
)

// GlobalUnicastV6 is the IPv6 range we drop: every currently-allocated
// global unicast address. Blocking this (and nothing below it) stops
// internet-bound IPv6 from leaking while leaving link-local/ULA/loopback
// intact.
const GlobalUnicastV6 = "2000::/3"

// Runner abstracts the OS-specific firewall calls. Implementations are
// stateful: BlockIPv6 records whatever it needs so Restore can reverse it.
type Runner interface {
	// BlockIPv6 installs rules that drop egress to GlobalUnicastV6.
	BlockIPv6() error
	// Restore removes everything BlockIPv6 installed.
	Restore() error
}

// Manager owns one BlockIPv6→Remove lifecycle. It is not safe for
// concurrent use: callers must serialize BlockIPv6 and Remove (the VPN
// client does so under its own mutex).
type Manager struct {
	log     *slog.Logger
	runner  Runner
	applied bool
}

// New returns a Manager backed by the platform's default Runner.
func New(log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{log: log, runner: newRunner()}
}

// newWithRunner is for tests.
func newWithRunner(log *slog.Logger, r Runner) *Manager {
	return &Manager{log: log, runner: r}
}

// BlockIPv6 installs the leak-protection rules. Calling it a second time
// without Remove is rejected — the runner has only one snapshot slot.
func (m *Manager) BlockIPv6() error {
	if m.applied {
		return fmt.Errorf("firewall: BlockIPv6 called twice without Remove in between")
	}
	if err := m.runner.BlockIPv6(); err != nil {
		return fmt.Errorf("firewall: block IPv6: %w", err)
	}
	m.applied = true
	m.log.Info("IPv6 leak protection enabled", "blocked", GlobalUnicastV6)
	return nil
}

// Remove tears down whatever BlockIPv6 installed. Errors are logged, not
// returned — Remove is meant to be deferred and run on shutdown.
func (m *Manager) Remove() {
	if !m.applied {
		return
	}
	if err := m.runner.Restore(); err != nil {
		m.log.Warn("IPv6 leak protection removal failed", "err", err)
		return
	}
	m.applied = false
	m.log.Debug("IPv6 leak protection removed")
}
