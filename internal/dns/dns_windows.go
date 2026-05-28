//go:build windows

package dns

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
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

func runNetsh(args []string) error {
	out, err := exec.Command("netsh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
