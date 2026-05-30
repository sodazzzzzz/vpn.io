//go:build linux

package firewall

import (
	"fmt"
	"os/exec"
	"strings"
)

// tableName is our dedicated nftables table. Keeping everything in a table
// we own means BlockIPv6 never touches the user's existing ruleset and
// Restore can drop the whole thing without parsing anything back out.
const tableName = "vpnio_leakguard"

// newRunner returns the Linux Runner, backed by nftables (`nft`).
func newRunner() Runner { return nftRunner{} }

type nftRunner struct{}

// BlockIPv6 (re)creates a dedicated inet table with an output-hook chain
// that drops egress to GlobalUnicastV6. The whole ruleset is loaded
// atomically from stdin; the add/delete/add dance makes it idempotent even
// if a previous run left the table behind (e.g. after a crash).
func (nftRunner) BlockIPv6() error {
	ruleset := fmt.Sprintf(`add table inet %[1]s
delete table inet %[1]s
add table inet %[1]s
add chain inet %[1]s output { type filter hook output priority 0 ; policy accept ; }
add rule inet %[1]s output ip6 daddr %[2]s drop
`, tableName, GlobalUnicastV6)
	return runNft(ruleset, "add", "table", "inet", tableName)
}

// Restore drops the whole table. It's a no-op-safe delete: Remove only
// calls us after BlockIPv6 succeeded, so the table is present.
func (nftRunner) Restore() error {
	return runNft("", "delete", "table", "inet", tableName)
}

// runNft runs `nft <args...>`. When stdin is non-empty it's fed to nft and
// the args are used purely for error messages (nft reads the ruleset from
// `-f -`).
func runNft(stdin string, args ...string) error {
	var cmd *exec.Cmd
	if stdin != "" {
		cmd = exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(stdin)
	} else {
		cmd = exec.Command("nft", args...)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
