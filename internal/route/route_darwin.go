//go:build darwin

package route

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
)

// newRunner returns the macOS Runner, backed by `/sbin/route` shellouts.
func newRunner() Runner { return darwinRunner{} }

type darwinRunner struct{}

// DefaultGateway parses `route -n get default` for the gateway line.
func (darwinRunner) DefaultGateway() (netip.Addr, error) {
	out, err := exec.Command("/sbin/route", "-n", "get", "default").CombinedOutput()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("route -n get default: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "gateway:") {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		addr, err := netip.ParseAddr(val)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("parse gateway %q: %w", val, err)
		}
		return addr, nil
	}
	return netip.Addr{}, fmt.Errorf("no gateway line in `route -n get default` output")
}

func (darwinRunner) AddRoute(p netip.Prefix, gw netip.Addr, iface string) error {
	return run(routeArgs("add", p, gw, iface))
}

func (darwinRunner) DelRoute(p netip.Prefix, gw netip.Addr, iface string) error {
	return run(routeArgs("delete", p, gw, iface))
}

// routeArgs renders a `/sbin/route <op> ...` command for macOS.
//
//   - /32 prefix     → `route <op> -host <ip> <gw>`
//   - any other CIDR → `route <op> -net <cidr> <gw>`
//
// iface is ignored — macOS resolves the outbound interface from the gateway.
func routeArgs(op string, p netip.Prefix, gw netip.Addr, _ string) []string {
	if p.Bits() == p.Addr().BitLen() {
		return []string{"/sbin/route", "-n", op, "-host", p.Addr().String(), gw.String()}
	}
	return []string{"/sbin/route", "-n", op, "-net", p.String(), gw.String()}
}

func run(argv []string) error {
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w (%s)", strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
