//go:build windows

package dns

import (
	"fmt"
	"log/slog"
	"strconv"

	"github.com/govpn/internal/execx"
)

func newRunner() Runner { return &windowsRunner{} }

type windowsRunner struct {
	iface string // saved so Restore knows what to revert
}

// Apply sets DNS on the TUN adapter. Windows uses per-adapter DNS, so as
// long as traffic for the resolver IPs flows over TUN (which it does once
// the routes are installed), these resolvers win for tunneled lookups.
func (w *windowsRunner) Apply(servers []string, iface string) error {
	if iface == "" {
		return fmt.Errorf("dns(windows): empty interface name")
	}
	if len(servers) == 0 {
		return nil
	}
	w.iface = iface
	primary := servers[0]
	args := []string{
		"interface", "ipv4", "set", "dnsservers",
		"name=" + iface, "static", primary, "primary",
	}
	if err := runNetsh(args); err != nil {
		return err
	}
	for i, s := range servers[1:] {
		args := []string{
			"interface", "ipv4", "add", "dnsservers",
			"name=" + iface, s, "index=" + strconv.Itoa(i+2),
		}
		if err := runNetsh(args); err != nil {
			// Best-effort rollback before bailing out.
			_ = w.Restore()
			return err
		}
	}
	return nil
}

// Restore reverts the TUN adapter to DHCP-supplied DNS (effectively none,
// since wintun doesn't speak DHCP — Windows falls back to the next
// adapter's resolvers, which is what we want).
func (w *windowsRunner) Restore() error {
	if w.iface == "" {
		return nil
	}
	err := runNetsh([]string{
		"interface", "ipv4", "set", "dnsservers",
		"name=" + w.iface, "dhcp",
	})
	w.iface = ""
	return err
}

// Clear is a near no-op on Windows: Apply sets DNS on the TUN adapter, which the
// OS destroys along with the process on a crash — taking the DNS override with
// it, so the host falls back to the physical adapter's resolvers on its own.
// Nothing durable is left to undo.
func (w *windowsRunner) Clear(_ *slog.Logger) error { return nil }

// Reconcile is a no-op for the same reason.
func (w *windowsRunner) Reconcile(_ *slog.Logger) error { return nil }

func runNetsh(args []string) error {
	return execx.Run("netsh", args...)
}
