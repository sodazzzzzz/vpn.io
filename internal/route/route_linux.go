//go:build linux

package route

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"strings"

	"github.com/govpn/internal/execx"
)

// newRunner returns the Linux Runner, backed by iproute2 (`ip`) shellouts.
func newRunner() Runner { return linuxRunner{} }

type linuxRunner struct{}

// DefaultGateway parses `ip -4 route show default` for the via clause.
func (linuxRunner) DefaultGateway() (netip.Addr, error) {
	out, err := execx.Output("ip", "-4", "route", "show", "default")
	if err != nil {
		return netip.Addr{}, err
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		// Expected: "default via 192.168.1.1 dev eth0 ..."
		for i, f := range fields {
			if f == "via" && i+1 < len(fields) {
				addr, err := netip.ParseAddr(fields[i+1])
				if err != nil {
					return netip.Addr{}, fmt.Errorf("parse gateway %q: %w", fields[i+1], err)
				}
				return addr, nil
			}
		}
	}
	return netip.Addr{}, fmt.Errorf("no `via` clause in default route output")
}

func (linuxRunner) AddRoute(p netip.Prefix, gw netip.Addr, iface string) error {
	args := []string{"ip", "-4", "route", "add", p.String(), "via", gw.String()}
	if iface != "" {
		args = append(args, "dev", iface)
	}
	return runLinux(args)
}

func (linuxRunner) DelRoute(p netip.Prefix, gw netip.Addr, iface string) error {
	args := []string{"ip", "-4", "route", "del", p.String(), "via", gw.String()}
	if iface != "" {
		args = append(args, "dev", iface)
	}
	return runLinux(args)
}

func runLinux(argv []string) error {
	return execx.Run(argv[0], argv[1:]...)
}
