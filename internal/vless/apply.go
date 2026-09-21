package vless

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DefaultUnit is the systemd unit the node runs Xray-core under.
const DefaultUnit = "vpn-xray"

// applyTimeout bounds how long WaitApplied watches for the service to come
// back. A restart of this service takes about a second, and the reload unit
// debounces for three, so this leaves room for both and still fails well inside
// a person's patience. Vars so tests need not wait them out.
var (
	applyTimeout = 30 * time.Second
	applyPoll    = 500 * time.Millisecond
)

// WaitApplied waits until the service is running again after a config change,
// and reports what went wrong if it is not.
//
// Nothing here restarts anything. The node applies a change by watching the
// config file: packaging/server/vpn-xray-reload.path notices the write and runs
// a root-owned oneshot that restarts the unit. That indirection exists because
// the writer is vpn-bot, a service with NoNewPrivileges=yes — it cannot gain
// privilege through sudo even if we gave it a rule, and handing it a way to
// restart arbitrary units would be a worse trade than letting systemd watch a
// file.
//
// What the writer can do, with no privilege at all, is ask systemd how the unit
// is doing. That is this function, and it is what turns "access was written to
// disk" into "access actually works" — without it a failed restart would leave
// someone holding a link that silently does nothing, and nobody would know
// until they said so.
func WaitApplied(ctx context.Context, unit string) error {
	if unit == "" {
		unit = DefaultUnit
	}
	ctx, cancel := context.WithTimeout(ctx, applyTimeout)
	defer cancel()

	var last string
	for {
		state, err := unitState(ctx, unit)
		if err == nil {
			switch state {
			case "active":
				return nil
			case "failed":
				// No point waiting out the timeout: systemd has given up.
				return fmt.Errorf("vless: %s failed to restart (systemctl status %s)", unit, unit)
			}
			last = state
		} else {
			last = err.Error()
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("vless: %s did not come back within %s (last state: %s)", unit, applyTimeout, last)
		case <-time.After(applyPoll):
		}
	}
}

// unitState asks systemd for the unit's ActiveState. Querying is unprivileged —
// it is a read over the system bus, not a change — so this works from the bot's
// sandbox exactly as it does from a root shell.
//
// A var so tests can answer without a systemd on the other end.
var unitState = func(ctx context.Context, unit string) (string, error) {
	out, err := exec.CommandContext(ctx, "systemctl", "show", "-p", "ActiveState", "--value", unit).Output()
	if err != nil {
		return "", fmt.Errorf("vless: query %s: %w", unit, err)
	}
	return strings.TrimSpace(string(out)), nil
}
