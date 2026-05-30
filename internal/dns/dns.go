// Package dns configures the OS resolver while the tunnel is up and
// restores the previous settings when it goes down.
//
// Implementations vary wildly:
//
//   - macOS:   `networksetup -setdnsservers` applied to every enabled
//     network service; original per-service settings are
//     remembered so Restore can put them back.
//   - Windows: `netsh interface ipv4 set dnsservers` against the TUN
//     adapter; Restore reverts that interface to DHCP.
//   - Linux:   resolvectl (systemd-resolved) when that service is active;
//     otherwise an atomic backup-and-rewrite of /etc/resolv.conf
//     (regular files and symlinks are both snapshotted and restored).
//
// The Manager type is the cross-platform façade; per-OS files supply a
// Runner via newRunner().
package dns

import (
	"fmt"
	"log/slog"
)

// Runner abstracts the OS-specific DNS calls. Implementations are stateful:
// Apply saves a snapshot internally so Restore can reverse it.
type Runner interface {
	Apply(servers []string, iface string) error
	Restore() error
}

// Manager owns one Apply→Restore lifecycle.
type Manager struct {
	log     *slog.Logger
	iface   string // TUN interface name (used by Windows; ignored elsewhere)
	runner  Runner
	applied bool
}

// New returns a Manager backed by the platform's default Runner.
func New(log *slog.Logger, iface string) *Manager {
	return &Manager{log: log, iface: iface, runner: newRunner()}
}

// newWithRunner is for tests.
func newWithRunner(log *slog.Logger, iface string, r Runner) *Manager {
	return &Manager{log: log, iface: iface, runner: r}
}

// Apply pushes servers as the active resolvers. Calling Apply a second time
// is rejected — the runner has only one snapshot slot.
func (m *Manager) Apply(servers []string) error {
	if len(servers) == 0 {
		return nil
	}
	if m.applied {
		return fmt.Errorf("dns: Apply called twice without Remove in between")
	}
	if err := m.runner.Apply(servers, m.iface); err != nil {
		return fmt.Errorf("dns: apply: %w", err)
	}
	m.applied = true
	m.log.Info("DNS configured", "servers", servers)
	return nil
}

// Remove restores the snapshot taken by Apply. Errors are logged, not
// returned — Remove is meant to be deferred and run on shutdown.
func (m *Manager) Remove() {
	if !m.applied {
		return
	}
	if err := m.runner.Restore(); err != nil {
		m.log.Warn("DNS restore failed", "err", err)
		return
	}
	m.applied = false
	m.log.Debug("DNS restored")
}
