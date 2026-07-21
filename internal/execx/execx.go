// Package execx runs external commands with a timeout, so a platform tool that
// wedges — networksetup during configd churn, resolvectl over a stuck D-Bus,
// ip/route/netsh/nft hanging on a busy stack — can't pin connect or teardown
// forever. Every shell-out in the route, dns, firewall and tun packages goes
// through here; before this, only dns_linux bounded its calls.
package execx

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DefaultTimeout bounds every external command. It's far above any healthy
// ip/route/netsh/networksetup/nft invocation (milliseconds) but well under the
// "hang forever" these tools are prone to.
const DefaultTimeout = 5 * time.Second

// Run executes name+args with DefaultTimeout, discarding output on success and
// wrapping it into the error on failure.
func Run(name string, args ...string) error {
	_, err := run(DefaultTimeout, nil, name, args...)
	return err
}

// Output is Run but returns the command's combined stdout+stderr.
func Output(name string, args ...string) ([]byte, error) {
	return run(DefaultTimeout, nil, name, args...)
}

// RunStdin executes name+args with DefaultTimeout, feeding stdin to the process
// (used for `nft -f -`).
func RunStdin(stdin []byte, name string, args ...string) error {
	_, err := run(DefaultTimeout, stdin, name, args...)
	return err
}

func run(timeout time.Duration, stdin []byte, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != nil {
		cmd.Stdin = strings.NewReader(string(stdin))
	}
	out, err := cmd.CombinedOutput()

	// A timeout surfaces as a kill signal on the process; report it as a timeout
	// explicitly rather than the opaque "signal: killed".
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return out, fmt.Errorf("execx: %s timed out after %s", name, timeout)
	}
	if err != nil {
		return out, fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}
