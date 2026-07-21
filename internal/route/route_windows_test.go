//go:build windows

package route

import (
	"net/netip"
	"testing"
)

// As4() panics on an IPv6 address, and this code runs in the privileged client
// process, so a prefix pushed by the server must never reach it unchecked.
// Manager.Install filters these out; this is the backstop at the syscall
// boundary, which must return an error rather than panic.
func TestPrefixToNetMask_RejectsIPv6(t *testing.T) {
	for _, p := range []string{"::/0", "2001:db8::/32"} {
		if _, _, err := prefixToNetMask(netip.MustParsePrefix(p)); err == nil {
			t.Errorf("prefixToNetMask(%s) succeeded, want error", p)
		}
	}

	dst, mask, err := prefixToNetMask(netip.MustParsePrefix("10.1.2.3/8"))
	if err != nil {
		t.Fatalf("prefixToNetMask(10.1.2.3/8): %v", err)
	}
	if dst != "10.0.0.0" || mask != "255.0.0.0" {
		t.Errorf("got dst=%s mask=%s, want 10.0.0.0 / 255.0.0.0", dst, mask)
	}
}

// AddRoute and DelRoute must surface the rejection instead of shelling out (or
// panicking) on a prefix they can't render.
func TestWindowsRunner_RejectsIPv6Prefix(t *testing.T) {
	var r windowsRunner
	p := netip.MustParsePrefix("2001:db8::/32")
	gw := netip.MustParseAddr("192.168.1.1")
	if err := r.AddRoute(p, gw, ""); err == nil {
		t.Error("AddRoute accepted an IPv6 prefix, want error")
	}
	if err := r.DelRoute(p, gw, ""); err == nil {
		t.Error("DelRoute accepted an IPv6 prefix, want error")
	}
}
