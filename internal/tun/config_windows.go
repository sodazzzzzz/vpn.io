//go:build windows

package tun

import (
	"fmt"
	"os/exec"
	"strconv"
)

// defaultTUNName is used when the caller leaves the interface name empty.
// Wintun needs a non-empty adapter name.
const defaultTUNName = "vpn.io"

// configureDevice assigns ip/netmask to the wintun adapter via netsh and
// sets its interface MTU. Requires Administrator.
//
// gateway is unused on Windows — for our /24 tunnel subnet the on-link
// route is created automatically by the static address assignment.
func configureDevice(name, ip, netmask, _gateway string, mtu int) error {
	// netsh: set the IPv4 address. The "name=" must be the wintun adapter's
	// friendly name (what Device.Name() returns).
	if err := run("netsh", "interface", "ipv4", "set", "address",
		"name="+name, "source=static", "address="+ip, "mask="+netmask); err != nil {
		return fmt.Errorf("tun: set address on %s: %w", name, err)
	}

	// netsh: set per-interface MTU.
	if err := run("netsh", "interface", "ipv4", "set", "subinterface",
		name, "mtu="+strconv.Itoa(mtu), "store=active"); err != nil {
		return fmt.Errorf("tun: set mtu on %s: %w", name, err)
	}
	return nil
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, string(out))
	}
	return nil
}
