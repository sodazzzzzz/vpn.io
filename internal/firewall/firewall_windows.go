//go:build windows

package firewall

import (
	"fmt"
	"os/exec"
	"strings"
)

// ruleName is the Windows Firewall rule we add and later delete by name.
const ruleName = "vpnio-leakguard-ipv6"

// newRunner returns the Windows Runner, backed by `netsh advfirewall`.
func newRunner() Runner { return netshRunner{} }

type netshRunner struct{}

// BlockIPv6 adds a single outbound block rule for GlobalUnicastV6. Block
// rules take precedence over allow rules in Windows Firewall, so this drops
// internet-bound IPv6 regardless of the default outbound policy.
func (netshRunner) BlockIPv6() error {
	// Drop any leftover rule from a previous crashed run first: netsh lets
	// several rules share a name, so a bare add could accumulate
	// duplicates. delete returns nonzero when nothing matches — expected,
	// so its error is ignored (mirrors the Linux add/delete/add idempotency).
	_ = runNetsh("advfirewall", "firewall", "delete", "rule", "name="+ruleName)
	return runNetsh(
		"advfirewall", "firewall", "add", "rule",
		"name="+ruleName,
		"dir=out", "action=block",
		"remoteip="+GlobalUnicastV6,
	)
}

// Restore deletes the rule by name.
func (netshRunner) Restore() error {
	return runNetsh("advfirewall", "firewall", "delete", "rule", "name="+ruleName)
}

func runNetsh(args ...string) error {
	out, err := exec.Command("netsh", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("netsh %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
