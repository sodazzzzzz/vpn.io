//go:build darwin

package route

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"strings"

	"github.com/govpn/internal/execx"
)

// newRunner returns the macOS Runner, backed by `/sbin/route` shellouts.
func newRunner() Runner { return darwinRunner{} }

type darwinRunner struct{}

// DefaultGateway returns the next-hop of the LITERAL default route (0.0.0.0/0).
//
// It deliberately does NOT use `route -n get default`: that does a
// longest-prefix-match lookup of 0.0.0.0, and while the tunnel's split-default
// (0.0.0.0/1 + 128.0.0.0/1) is installed, the lookup matches those more-specific
// routes and returns the TUNNEL gateway. The caller's "is this the tun gateway?"
// guard then fires every time and the server pin-hole is never re-pinned, so a
// reconnect after a network change black-holes (#129). `netstat` lists each
// route as its own row, so we read the one whose destination is exactly
// "default" — the host's real gateway, unaffected by our split routes.
func (darwinRunner) DefaultGateway() (netip.Addr, error) {
	out, err := execx.Output("/usr/sbin/netstat", "-rnf", "inet")
	if err != nil {
		return netip.Addr{}, err
	}
	return parseDefaultGateway(out)
}

// parseDefaultGateway extracts the gateway of the literal default route from
// `netstat -rnf inet` output. Split out from the shellout so it can be tested.
func parseDefaultGateway(out []byte) (netip.Addr, error) {
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || fields[0] != "default" {
			continue
		}
		// A default route can point at an interface (e.g. "link#5") on
		// point-to-point links rather than an IP next-hop; skip those and keep
		// looking — they aren't a gateway we can pin a host route through.
		addr, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue
		}
		return addr, nil
	}
	if err := sc.Err(); err != nil {
		return netip.Addr{}, fmt.Errorf("scan netstat output: %w", err)
	}
	return netip.Addr{}, fmt.Errorf("no default route with an IP gateway in netstat output")
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
	return execx.Run(argv[0], argv[1:]...)
}
