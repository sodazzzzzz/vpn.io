//go:build linux

package firewall

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// tableName is our dedicated nftables table. Keeping everything in a table
// we own means BlockIPv6 never touches the user's existing ruleset and
// Restore can drop the whole thing without parsing anything back out.
const tableName = "vpnio_leakguard"

// newRunner returns the Linux Runner, backed by nftables (`nft`). The
// logger is unused here — nft failures are returned to the Manager, which
// logs them.
func newRunner(*slog.Logger) Runner { return nftRunner{} }

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
	return runNft(ruleset, "load leakguard ruleset")
}

// Restore drops the whole table. It's a no-op-safe delete: Remove only
// calls us after BlockIPv6 succeeded, so the table is present.
func (nftRunner) Restore() error {
	return runNft("", "delete", "table", "inet", tableName)
}

// runNft runs nft. When ruleset is non-empty it's loaded atomically via
// `nft -f -` and label is used only as error context (a human description
// of the whole ruleset, since no single argv represents it). Otherwise
// label is the literal `nft` argument vector.
func runNft(ruleset string, label ...string) error {
	var cmd *exec.Cmd
	if ruleset != "" {
		cmd = exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(ruleset)
	} else {
		cmd = exec.Command("nft", label...)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		desc := "nft " + strings.Join(label, " ")
		if ruleset != "" {
			desc = "nft -f - (" + strings.Join(label, " ") + ")"
		}
		return fmt.Errorf("%s: %w (%s)", desc, err, strings.TrimSpace(string(out)))
	}
	return nil
}
