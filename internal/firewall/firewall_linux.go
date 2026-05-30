//go:build linux

package firewall

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// tableName is our dedicated nftables table. Keeping everything in a table
// we own means Enable never touches the user's existing ruleset and Restore
// can drop the whole thing without parsing anything back out.
const tableName = "vpnio_leakguard"

// lanPrefixes are the destination ranges allowed through the kill-switch
// when AllowLAN is set: RFC1918 private space, link-local, multicast and
// the limited broadcast address. None are internet-routable, so permitting
// them keeps LAN devices reachable without opening an external leak.
//
// Intentionally IPv4-only: the data plane is IPv4, and all IPv6 is dropped
// by the chain's default policy regardless of AllowLAN (no v6 LAN/ULA path).
var lanPrefixes = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"169.254.0.0/16",
	"224.0.0.0/4",
	"255.255.255.255/32",
}

// newRunner returns the Linux Runner, backed by nftables (`nft`). The
// logger is unused here — nft failures are returned to the Manager, which
// logs them.
func newRunner(*slog.Logger) Runner { return nftRunner{} }

type nftRunner struct{}

// Enable installs the kill-switch: a dedicated inet table with an
// output-hook chain whose default policy is drop, so only the explicitly
// accepted egress (loopback, the tunnel interface, the server pin-hole,
// DHCP and — by policy — local networks) can leave the host. Everything
// else, including all routable IPv6, is dropped, so a tunnel that drops
// can't leak.
//
// Any leftover table from a crashed run is dropped first as a separate
// best-effort command, so the atomic create below starts clean — and works
// even on old nft (<0.9.1), where `add` on an already-present table would
// abort the whole `-f -` batch.
func (nftRunner) Enable(cfg Config) error {
	// Ignore the delete error: it's expected when no stale table exists.
	_ = runNftArgs("delete", "table", "inet", tableName)
	return runNftFile(buildKillSwitchRuleset(cfg), "load kill-switch ruleset")
}

// buildKillSwitchRuleset renders the `nft -f -` script for cfg. Kept pure
// (no I/O) so it can be unit-tested.
func buildKillSwitchRuleset(cfg Config) string {
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %[1]s\n", tableName)
	fmt.Fprintf(&b, "add chain inet %[1]s output { type filter hook output priority 0 ; policy drop ; }\n", tableName)

	// Loopback is always allowed (covers both v4 and v6 on lo).
	fmt.Fprintf(&b, "add rule inet %s output oifname \"lo\" accept\n", tableName)

	// Tunneled traffic leaves via the TUN interface.
	if cfg.TunIface != "" {
		fmt.Fprintf(&b, "add rule inet %s output oifname %q accept\n", tableName, cfg.TunIface)
	}

	// The tunnel transport to the server must survive the kill-switch,
	// otherwise the tunnel could never (re)connect. nftables' `ip daddr` is
	// IPv4-only, so use `ip6 daddr` for a v6 server — the transport may run
	// over IPv6 even though the data plane is IPv4.
	if cfg.ServerIP.IsValid() {
		fam := "ip"
		if cfg.ServerIP.Is6() {
			fam = "ip6"
		}
		fmt.Fprintf(&b, "add rule inet %s output %s daddr %s accept\n", tableName, fam, cfg.ServerIP)
	}

	// DHCP client, so the lease can renew while the switch is up. Matches
	// the broadcast DISCOVER and unicast REQUEST regardless of destination.
	fmt.Fprintf(&b, "add rule inet %s output udp sport 68 udp dport 67 accept\n", tableName)

	// Local networks, if policy permits.
	if cfg.AllowLAN {
		fmt.Fprintf(&b, "add rule inet %s output ip daddr { %s } accept\n", tableName, strings.Join(lanPrefixes, ", "))
	}

	return b.String()
}

// Restore drops the whole table. Remove only calls us after Enable
// succeeded, so the table is present.
func (nftRunner) Restore() error {
	return runNftArgs("delete", "table", "inet", tableName)
}

// Clear removes the table regardless of in-process state — the cross-process
// escape hatch. `nft delete table` is stateless, so it works even from a
// fresh process recovering after a crash.
func (nftRunner) Clear() error {
	return runNftArgs("delete", "table", "inet", tableName)
}

// runNftArgs runs `nft <args...>`.
func runNftArgs(args ...string) error {
	out, err := exec.Command("nft", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runNftFile loads ruleset atomically via `nft -f -`. label is purely
// error context — no single argv represents the whole ruleset.
func runNftFile(ruleset, label string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft -f - (%s): %w (%s)", label, err, strings.TrimSpace(string(out)))
	}
	return nil
}
