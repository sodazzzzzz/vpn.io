// Package route installs and rolls back the system routes that turn a
// freshly configured TUN interface into a working tunnel.
//
// Two pieces of state need to change for a full-tunnel client:
//
//  1. A pin-hole host route to the VPN server through the *original* default
//     gateway, so the TLS connection that carries the tunnel doesn't try to
//     route itself through the tunnel and deadlock.
//  2. The pushed routes (e.g. "0.0.0.0/0" for full-tunnel) via the tunnel
//     gateway.
//
// The Manager records every route it adds and removes them in reverse on
// shutdown. Mistakes are logged at warn level — we don't want one stuck
// route to block the client's exit.
//
// The 0.0.0.0/0 push is translated into a 0.0.0.0/1 + 128.0.0.0/1 pair so
// the kernel's pre-existing default route doesn't need to be removed (this
// is OpenVPN's "redirect-gateway def1" technique). Restoring control on
// disconnect is then "delete the two halves" — no risk of leaving the host
// without a default route if something goes wrong.
package route

import (
	"fmt"
	"log/slog"
	"net/netip"
)

// Runner abstracts the OS-specific system calls. Per-OS files provide a
// concrete implementation via newRunner(); tests can swap in their own.
type Runner interface {
	// DefaultGateway returns the current default gateway used for the
	// (presumed IPv4) route 0.0.0.0/0.
	DefaultGateway() (netip.Addr, error)

	// AddRoute installs prefix via gw. iface may be empty when the OS can
	// infer it from gw; it's a hint, not a guarantee.
	AddRoute(prefix netip.Prefix, gw netip.Addr, iface string) error

	// DelRoute removes a route previously installed with AddRoute. iface must
	// be the same value AddRoute was given: on Linux `ip route del` matches on
	// the full selector, so naming a different device (or any device for a
	// route added without one) fails to match and leaves the route in place.
	DelRoute(prefix netip.Prefix, gw netip.Addr, iface string) error
}

// Manager owns the routes it installed and knows how to remove them.
type Manager struct {
	log    *slog.Logger
	iface  string     // TUN interface name (hint for platforms that need it)
	tunGW  netip.Addr // tunnel-side gateway (e.g. 10.8.0.1)
	server netip.Addr // VPN server's reachable IP (for the pin-hole route)
	runner Runner

	pinholeGW netip.Addr     // original default gw, captured at Install time
	installed []installedKey // for reverse-order rollback
}

type installedKey struct {
	prefix netip.Prefix
	gw     netip.Addr
	// iface is the hint the route was *added* with, and removal must reuse it
	// verbatim. The pin-hole is added with iface="" so the kernel binds it to
	// the physical link; deleting it with the TUN's name instead makes the
	// selector miss and leaves a stale host route to the VPN server behind
	// after every disconnect.
	iface string
}

// New constructs a Manager backed by the platform's default Runner. The
// server argument is the host IP the VPN client actually connected to,
// used for the pin-hole route.
func New(log *slog.Logger, iface string, tunGW, server netip.Addr) *Manager {
	return &Manager{
		log:    log,
		iface:  iface,
		tunGW:  tunGW,
		server: server,
		runner: newRunner(),
	}
}

// newWithRunner is for tests.
func newWithRunner(log *slog.Logger, iface string, tunGW, server netip.Addr, r Runner) *Manager {
	return &Manager{log: log, iface: iface, tunGW: tunGW, server: server, runner: r}
}

// Install adds the pin-hole route and every pushed CIDR. If any step fails,
// already-added routes are rolled back before returning.
func (m *Manager) Install(cidrs []string) error {
	if !m.server.IsValid() {
		return fmt.Errorf("route: server IP not set")
	}
	if !m.tunGW.IsValid() {
		return fmt.Errorf("route: tunnel gateway not set")
	}

	gw, err := m.runner.DefaultGateway()
	if err != nil {
		return fmt.Errorf("route: query default gateway: %w", err)
	}
	m.pinholeGW = gw

	// 1. Pin-hole host route to the server via the original default gw.
	pinhole := netip.PrefixFrom(m.server, m.server.BitLen())
	if err := m.add(pinhole, gw, ""); err != nil {
		return fmt.Errorf("route: install pin-hole %s via %s: %w", pinhole, gw, err)
	}

	// 2. Pushed routes — via the tunnel gateway, expanded if needed.
	for _, raw := range cidrs {
		prefix, perr := netip.ParsePrefix(raw)
		if perr != nil {
			m.rollback()
			return fmt.Errorf("route: parse push %q: %w", raw, perr)
		}
		for _, p := range expandDefault(prefix) {
			if err := m.add(p, m.tunGW, m.iface); err != nil {
				m.rollback()
				return fmt.Errorf("route: install push %s: %w", p, err)
			}
		}
	}
	return nil
}

// Remove undoes every Install change in reverse order. Errors are logged
// but not returned — Remove is meant to be deferred and run on shutdown.
func (m *Manager) Remove() {
	m.rollback()
}

// RefreshServerPinhole re-pins the host route to the VPN server through the
// gateway that is the default *now*. The pin-hole is installed once at Install
// time via whatever gateway existed then; a network change (e.g. Wi-Fi drop
// then rejoin) can flush it or leave it pointing at a gateway that no longer
// exists. With the pin-hole gone, the server's IP falls under the tunnel
// split-routes (128.0.0.0/1 via the tunnel gateway) and a reconnect dial
// blackholes into the now-dead tunnel — the connection can never recover on
// its own. Calling this before each reconnect dial re-asserts the pin-hole via
// the current default gateway, keeping the control connection routable across
// network changes. Safe to call repeatedly.
func (m *Manager) RefreshServerPinhole() error {
	if !m.server.IsValid() {
		return fmt.Errorf("route: server IP not set")
	}
	gw, err := m.runner.DefaultGateway()
	if err != nil {
		return fmt.Errorf("route: refresh pin-hole, query default gateway: %w", err)
	}
	// Guard against the default-gateway query resolving to the tunnel itself.
	// The split-routes (0.0.0.0/1 + 128.0.0.0/1) point at the tunnel gateway and
	// are still present on a reconnect; an OS whose "default route" lookup honours
	// longest-prefix (rather than the literal 0.0.0.0/0 entry) can hand back the
	// tunnel gateway. Pinning the server through it would route the control
	// connection into the very tunnel it carries — worse than doing nothing — so
	// skip and let the caller retry.
	if gw == m.tunGW {
		return fmt.Errorf("route: default gateway resolved to tunnel %s; skipping pin-hole refresh", gw)
	}
	pinhole := netip.PrefixFrom(m.server, m.server.BitLen())

	// Drop the previous pin-hole and re-add it via the current gateway. The old
	// one may be stale or already flushed by the OS, so a delete failure is
	// expected here and only logged.
	if m.pinholeGW.IsValid() {
		if err := m.runner.DelRoute(pinhole, m.pinholeGW, ""); err != nil {
			m.log.Debug("refresh pin-hole: stale delete failed (expected)", "via", m.pinholeGW, "err", err)
		}
	}
	if err := m.runner.AddRoute(pinhole, gw, ""); err != nil {
		return fmt.Errorf("route: refresh pin-hole %s via %s: %w", pinhole, gw, err)
	}
	m.pinholeGW = gw

	// Keep the rollback record pointing at the live pin-hole so shutdown removes
	// the right route.
	for i := range m.installed {
		if m.installed[i].prefix == pinhole {
			m.installed[i].gw = gw
			break
		}
	}
	m.log.Debug("server pin-hole refreshed", "server", m.server, "via", gw)
	return nil
}

func (m *Manager) add(p netip.Prefix, gw netip.Addr, iface string) error {
	if err := m.runner.AddRoute(p, gw, iface); err != nil {
		return err
	}
	m.installed = append(m.installed, installedKey{prefix: p, gw: gw, iface: iface})
	m.log.Debug("route added", "prefix", p, "via", gw)
	return nil
}

func (m *Manager) rollback() {
	for i := len(m.installed) - 1; i >= 0; i-- {
		k := m.installed[i]
		if err := m.runner.DelRoute(k.prefix, k.gw, k.iface); err != nil {
			m.log.Warn("route removal failed", "prefix", k.prefix, "via", k.gw, "err", err)
			continue
		}
		m.log.Debug("route removed", "prefix", k.prefix, "via", k.gw)
	}
	m.installed = nil
}

// expandDefault rewrites the IPv4 default route as two /1 halves so the
// kernel's pre-existing default doesn't need to be touched. Other prefixes
// pass through unchanged.
func expandDefault(p netip.Prefix) []netip.Prefix {
	if p.Bits() != 0 || !p.Addr().Is4() {
		return []netip.Prefix{p}
	}
	return []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/1"),
		netip.MustParsePrefix("128.0.0.0/1"),
	}
}
