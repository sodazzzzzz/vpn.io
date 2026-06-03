//go:build linux

package tun

import (
	"fmt"
	"os/exec"
	"strconv"
)

// defaultTUNName is used when the caller leaves the interface name empty.
// An empty name lets the kernel auto-assign the next free tunN.
const defaultTUNName = ""

// configureDevice assigns ip/netmask to the named interface and brings it up
// using iproute2 (`ip` command). Requires CAP_NET_ADMIN (typically root).
//
// gateway is unused on Linux — a /N prefix on a normal (non point-to-point)
// TUN interface implies the subnet, and the kernel installs an on-link route
// for the prefix automatically.
func configureDevice(name, ip, netmask, _gateway string, mtu int) error {
	prefix, err := netmaskToPrefixLen(netmask)
	if err != nil {
		return err
	}
	addr := fmt.Sprintf("%s/%d", ip, prefix)

	if err := run("ip", "addr", "add", addr, "dev", name); err != nil {
		return fmt.Errorf("tun: assign %s to %s: %w", addr, name, err)
	}
	if err := run("ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu)); err != nil {
		return fmt.Errorf("tun: set mtu on %s: %w", name, err)
	}
	if err := run("ip", "link", "set", "dev", name, "up"); err != nil {
		return fmt.Errorf("tun: bring %s up: %w", name, err)
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
