//go:build linux

package dns

import "log/slog"

// On Linux the resolver is managed by an unbounded variety of components
// (systemd-resolved, NetworkManager, resolvconf, plain /etc/resolv.conf…)
// and a learning-grade VPN shouldn't pick a single mechanism and pretend
// it covers every distro. The runner here logs once and returns nil so
// the rest of the client doesn't fail; users on Linux should configure
// DNS manually using the IPs printed by the server's push.
func newRunner() Runner { return linuxRunner{} }

type linuxRunner struct{}

func (linuxRunner) Apply(servers []string, _ string) error {
	slog.Default().Warn(
		"DNS push received on Linux but no automatic configuration is wired up; configure /etc/resolv.conf manually",
		"servers", servers,
	)
	return nil
}

func (linuxRunner) Restore() error { return nil }
