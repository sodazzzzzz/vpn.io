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
// that drops egress to GlobalUnicastV6. Any leftover table from a crashed
// run is dropped first as a separate best-effort command, so the atomic
// create below starts clean — and works even on old nft (<0.9.1), where
// `add` on an already-present table would abort the whole `-f -` batch.
func (nftRunner) BlockIPv6() error {
	// Ignore the delete error: it's expected when no stale table exists.
	_ = runNftArgs("delete", "table", "inet", tableName)
	ruleset := fmt.Sprintf(`add table inet %[1]s
add chain inet %[1]s output { type filter hook output priority 0 ; policy accept ; }
add rule inet %[1]s output ip6 daddr %[2]s drop
`, tableName, GlobalUnicastV6)
	return runNftFile(ruleset, "load leakguard ruleset")
}

// Restore drops the whole table. It's a no-op-safe delete: Remove only
// calls us after BlockIPv6 succeeded, so the table is present.
func (nftRunner) Restore() error {
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
