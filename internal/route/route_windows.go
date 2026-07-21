//go:build windows

package route

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// newRunner returns the Windows Runner, backed by the `route.exe` and
// `netsh` shellouts.
func newRunner() Runner { return windowsRunner{} }

type windowsRunner struct{}

// DefaultGateway parses `route print 0.0.0.0` for the lowest-metric IPv4
// default route's gateway. Output looks like:
//
//	IPv4 Route Table
//	===========================================================================
//	Active Routes:
//	Network Destination        Netmask          Gateway       Interface  Metric
//	          0.0.0.0          0.0.0.0      192.168.1.1   192.168.1.34     25
func (windowsRunner) DefaultGateway() (netip.Addr, error) {
	out, err := exec.Command("route", "print", "0.0.0.0").CombinedOutput()
	if err != nil {
		return netip.Addr{}, fmt.Errorf("route print: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	var (
		best       netip.Addr
		bestMetric = int(^uint(0) >> 1) // max int
	)
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 5 {
			continue
		}
		if fields[0] != "0.0.0.0" || fields[1] != "0.0.0.0" {
			continue
		}
		gw, err := netip.ParseAddr(fields[2])
		if err != nil {
			continue
		}
		var metric int
		if _, err := fmt.Sscanf(fields[4], "%d", &metric); err != nil {
			continue
		}
		if metric < bestMetric {
			bestMetric = metric
			best = gw
		}
	}
	if !best.IsValid() {
		return netip.Addr{}, fmt.Errorf("no default route found in `route print` output")
	}
	return best, nil
}

func (windowsRunner) AddRoute(p netip.Prefix, gw netip.Addr, iface string) error {
	dst, mask, err := prefixToNetMask(p)
	if err != nil {
		return err
	}
	argv := []string{"route", "ADD", dst, "MASK", mask, gw.String()}
	// Pin the route to iface when one is given. Without "IF <index>", Windows
	// picks the interface itself from the gateway, and for a tunnel gateway
	// (e.g. 10.8.0.1) it can bind the route to the physical adapter instead of
	// the TUN — the route then sits on the wrong interface and traffic skips the
	// tunnel. The pin-hole passes iface="" and keeps the OS's choice.
	if iface != "" {
		idx, err := ifaceIndex(iface)
		if err != nil {
			return fmt.Errorf("route: resolve interface %q: %w", iface, err)
		}
		argv = append(argv, "IF", strconv.Itoa(idx))
	}
	return runWin(argv)
}

func (windowsRunner) DelRoute(p netip.Prefix, gw netip.Addr, _ string) error {
	dst, _, err := prefixToNetMask(p)
	if err != nil {
		return err
	}
	// Delete matches on destination + gateway, which is unique here, so it
	// removes the route regardless of the interface it ended up on.
	return runWin([]string{"route", "DELETE", dst, gw.String()})
}

// ifaceIndex resolves a Windows interface (friendly) name to its numeric index
// for `route add ... IF <n>`.
func ifaceIndex(name string) (int, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return 0, err
	}
	return ifi.Index, nil
}

// prefixToNetMask renders p as the "dotted-quad destination + dotted-quad
// netmask" pair that `route ADD/DELETE` expects. It rejects non-IPv4 prefixes:
// `route` speaks IPv4 here, and As4() panics on an IPv6 address — which, in
// this privileged process, would take down the whole client on a prefix pushed
// by the server. Manager.Install already filters these out; this is the
// backstop at the syscall boundary.
func prefixToNetMask(p netip.Prefix) (string, string, error) {
	if !p.Addr().Is4() {
		return "", "", fmt.Errorf("route: %s is not an IPv4 prefix", p)
	}
	addr := p.Addr().As4()
	bits := p.Bits()
	var mask [4]byte
	for i := 0; i < bits; i++ {
		mask[i/8] |= 1 << (7 - i%8)
	}
	netIP := netip.AddrFrom4([4]byte{
		addr[0] & mask[0], addr[1] & mask[1], addr[2] & mask[2], addr[3] & mask[3],
	})
	maskIP := netip.AddrFrom4(mask)
	return netIP.String(), maskIP.String(), nil
}

func runWin(argv []string) error {
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w (%s)", strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
