//go:build darwin

package tun

import (
	"fmt"
	"os/exec"
	"strconv"
)

// configureDevice configures a utun interface on macOS via ifconfig.
//
// utun is strictly point-to-point: ifconfig requires both the local IP and
// a peer (destination) IP. We use the tunnel gateway as the peer; the rest
// of the /24 subnet is reached via routes installed by the caller.
//
// Requires root.
func configureDevice(name, ip, netmask, gateway string, mtu int) error {
	if gateway == "" {
		return fmt.Errorf("tun: macOS requires a non-empty gateway/peer address")
	}
	return run("ifconfig", name, "inet", ip, gateway,
		"netmask", netmask, "mtu", strconv.Itoa(mtu), "up")
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w: %s", name, args, err, string(out))
	}
	return nil
}
