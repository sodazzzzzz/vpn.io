package main

import (
	"log/slog"
	"os"
	"runtime"
	"strings"
)

// warnIfForwardingDisabled prints a hint when net.ipv4.ip_forward is off on
// Linux. The server itself doesn't touch the sysctl — that's scripts/setup-nat.sh's
// job — but a silently misconfigured host is the most common reason new users
// see "tunnel is up but I can't reach the internet". A single early warning is
// cheaper than walking them through diagnosis later.
func warnIfForwardingDisabled(log *slog.Logger) {
	if runtime.GOOS != "linux" {
		return
	}
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	if err != nil {
		return // not fatal — kernel without /proc or permissions
	}
	if strings.TrimSpace(string(data)) == "0" {
		log.Warn(
			"IPv4 forwarding is OFF — clients won't reach the public internet through this server. " +
				"Run scripts/setup-nat.sh <subnet> <wan-iface> as root to enable forwarding and NAT.",
		)
	}
}
