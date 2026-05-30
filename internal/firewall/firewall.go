// Package firewall installs OS-level leak-protection rules while a
// full-tunnel session is up and removes them when it goes down.
//
// What it enforces depends on the OS:
//
//   - Linux: a kill-switch. While the tunnel is up, egress is default-deny
//     and only the necessary traffic is allowed (loopback, the tunnel
//     interface, the VPN server pin-hole, DHCP, and — by policy — local
//     networks). If the tunnel drops, nothing escapes to the open network.
//     Dropping everything un-allowed also stops IPv6 leaks for free.
//   - macOS / Windows: an IPv6-only block. The data plane is IPv4-only, so
//     a full-tunnel client that redirects just the IPv4 default would leak
//     all IPv6 out the host's untouched IPv6 default route. Dropping
//     routable IPv6 makes dual-stack apps fall back to IPv4, which the
//     tunnel carries. A full kill-switch on these OSes (pf / WFP) is a
//     follow-up.
//
// The Manager type is the cross-platform façade with a single
// Enable→Remove lifecycle (mirroring internal/dns and internal/route);
// per-OS files supply a Runner via newRunner().
//
// Crash semantics: on a clean Remove the rules come down. If the client is
// killed without cleanup the Linux kill-switch INTENTIONALLY stays in
// place — that's the point, a dead client must not leak. Recover a stuck
// network with the package-level Clear (exposed as `vpn-client
// --clear-firewall`) or, on Linux, `sudo nft delete table inet
// vpnio_leakguard`.
package firewall

import (
	"fmt"
	"log/slog"
	"net/netip"
)

// GlobalUnicastV6 is the IPv6 range the IPv6-only backends (macOS/Windows)
// drop: every currently-allocated global unicast address. Blocking this
// (and nothing below it) stops internet-bound IPv6 from leaking while
// leaving link-local/ULA/loopback intact.
const GlobalUnicastV6 = "2000::/3"

// Config describes the full-tunnel session the leak protection guards.
// The IPv6-only backends ignore everything except the fact that protection
// is wanted; the Linux kill-switch uses all of it.
type Config struct {
	ServerIP netip.Addr // VPN server, allowed through the kill-switch (transport pin-hole)
	TunIface string     // tunnel interface whose egress is allowed
	AllowLAN bool       // permit local/RFC1918 networks through the kill-switch
}

// Runner abstracts the OS-specific firewall calls. Implementations are
// stateful: Enable records whatever it needs so Restore can reverse it.
type Runner interface {
	// Enable installs leak protection for the session described by cfg.
	Enable(cfg Config) error
	// Restore removes everything Enable installed.
	Restore() error
	// Clear unconditionally removes our leak-protection rules without
	// relying on in-process state — the escape hatch for a network left
	// locked by a crashed client. Best-effort.
	Clear() error
}

// Manager owns one Enable→Remove lifecycle. It is not safe for concurrent
// use: callers must serialize Enable and Remove (the VPN client does so
// under its own mutex).
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
	return &Manager{log: log, runner: newRunner(log)}
}

// newWithRunner is for tests.
func newWithRunner(log *slog.Logger, r Runner) *Manager {
	return &Manager{log: log, runner: r}
}

// Enable installs the leak-protection rules. Calling it a second time
// without Remove is rejected — the runner has only one snapshot slot.
func (m *Manager) Enable(cfg Config) error {
	if m.applied {
		return fmt.Errorf("firewall: Enable called twice without Remove in between")
	}
	if err := m.runner.Enable(cfg); err != nil {
		return fmt.Errorf("firewall: enable: %w", err)
	}
	m.applied = true
	m.log.Info("leak protection enabled", "server", cfg.ServerIP, "tun", cfg.TunIface, "allow-lan", cfg.AllowLAN)
	return nil
}

// Remove tears down whatever Enable installed. Errors are logged, not
// returned — Remove is meant to be deferred and run on shutdown.
func (m *Manager) Remove() {
	if !m.applied {
		return
	}
	if err := m.runner.Restore(); err != nil {
		m.log.Warn("leak protection removal failed", "err", err)
		return
	}
	m.applied = false
	m.log.Debug("leak protection removed")
}

// Clear removes any leak-protection rules left behind by a previous run,
// without needing a Manager or session state. Use it to recover a network
// a crashed client left locked. Best-effort.
func Clear(log *slog.Logger) error {
	if log == nil {
		log = slog.Default()
	}
	return newRunner(log).Clear()
}
