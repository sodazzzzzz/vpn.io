//go:build darwin

package route

// Live check for #196 on darwin: the real shell-out path now goes through
// internal/execx (timeout-bounded). DefaultGateway() runs `/usr/sbin/netstat`
// through execx.Output and parses the literal default route — read-only, no
// mutation of the host's network config. We confirm it returns the machine's
// actual default gateway, cross-checked against an independent `route -n get
// default` read that does NOT go through execx. This exercises real tool +
// real args + the new wrapper end-to-end. (The mutating darwin shell-outs —
// AddRoute/DelRoute/dns/firewall — can only be exercised under a privileged
// live tunnel, which would reroute the host's traffic and is out of scope here.)

import (
	"os/exec"
	"strings"
	"testing"
)

func TestLive_DefaultGatewayThroughExecx(t *testing.T) {
	gw, err := newRunner().DefaultGateway()
	if err != nil {
		t.Fatalf("DefaultGateway() via execx: %v", err)
	}
	if !gw.Is4() {
		t.Fatalf("DefaultGateway() = %v, want an IPv4 next-hop", gw)
	}

	// Independent oracle: `route -n get default` reports the same next-hop by a
	// different code path (not through execx). If they disagree, either execx
	// mangled the invocation or the parse is wrong.
	out, err := exec.Command("/sbin/route", "-n", "get", "default").CombinedOutput()
	if err != nil {
		t.Skipf("oracle `route -n get default` unavailable: %v", err)
	}
	var want string
	for line := range strings.SplitSeq(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "gateway:" {
			want = f[1]
			break
		}
	}
	if want == "" {
		t.Skipf("oracle reported no IP gateway (default may be a link route):\n%s", out)
	}
	if gw.String() != want {
		t.Errorf("execx path gateway = %s, oracle = %s", gw, want)
	}
}
