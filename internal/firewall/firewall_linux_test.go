//go:build linux

package firewall

import (
	"net/netip"
	"strings"
	"testing"
)

func TestBuildKillSwitchRuleset_FullTunnelAllowLAN(t *testing.T) {
	rs := buildKillSwitchRuleset(Config{
		ServerIP: netip.MustParseAddr("203.0.113.5"),
		TunIface: "tun0",
		AllowLAN: true,
	})

	mustContain := []string{
		"add table inet vpnio_leakguard",
		"hook output priority 0 ; policy drop", // default-deny
		`oifname "lo" accept`,                  // loopback
		`oifname "tun0" accept`,                // tunnel egress
		"ip daddr 203.0.113.5 accept",          // server pin-hole
		"udp sport 68 udp dport 67 accept",     // DHCP client
		"10.0.0.0/8",                           // LAN set present
		"192.168.0.0/16",
		"255.255.255.255/32",
	}
	for _, want := range mustContain {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset missing %q\n---\n%s", want, rs)
		}
	}
}

func TestBuildKillSwitchRuleset_StrictOmitsLAN(t *testing.T) {
	rs := buildKillSwitchRuleset(Config{
		ServerIP: netip.MustParseAddr("203.0.113.5"),
		TunIface: "tun0",
		AllowLAN: false,
	})
	if strings.Contains(rs, "10.0.0.0/8") || strings.Contains(rs, "192.168.0.0/16") {
		t.Errorf("strict ruleset must not allow LAN ranges\n---\n%s", rs)
	}
	// The essentials are still there even in strict mode.
	for _, want := range []string{`oifname "tun0" accept`, "ip daddr 203.0.113.5 accept", "udp sport 68 udp dport 67 accept"} {
		if !strings.Contains(rs, want) {
			t.Errorf("strict ruleset missing essential rule %q\n---\n%s", want, rs)
		}
	}
}

func TestBuildKillSwitchRuleset_OmitsUnsetServerAndTun(t *testing.T) {
	rs := buildKillSwitchRuleset(Config{AllowLAN: false})
	if strings.Contains(rs, "ip daddr  accept") || strings.Contains(rs, "oifname \"\" accept") {
		t.Errorf("ruleset emitted a rule for an unset field\n---\n%s", rs)
	}
	// Loopback and the drop policy are unconditional.
	for _, want := range []string{`oifname "lo" accept`, "policy drop"} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset missing unconditional rule %q\n---\n%s", want, rs)
		}
	}
}
