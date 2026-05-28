//go:build windows

package route

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"os/exec"
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

func (windowsRunner) AddRoute(p netip.Prefix, gw netip.Addr, _ string) error {
	net, mask := prefixToNetMask(p)
	return runWin([]string{"route", "ADD", net, "MASK", mask, gw.String()})
}

func (windowsRunner) DelRoute(p netip.Prefix, gw netip.Addr, _ string) error {
	net, _ := prefixToNetMask(p)
	return runWin([]string{"route", "DELETE", net, gw.String()})
}

func prefixToNetMask(p netip.Prefix) (string, string) {
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
	return netIP.String(), maskIP.String()
}

func runWin(argv []string) error {
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w (%s)", strings.Join(argv, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
