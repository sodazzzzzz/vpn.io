//go:build darwin

package tun

import (
	"fmt"
	"strconv"

	"github.com/govpn/internal/execx"
)

// defaultTUNName is used when the caller leaves the interface name empty.
// macOS rejects an empty name (it must match utun[0-9]*); "utun" tells the
// kernel to pick the next free utunN.
const defaultTUNName = "utun"

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
	return execx.Run(name, args...)
}
