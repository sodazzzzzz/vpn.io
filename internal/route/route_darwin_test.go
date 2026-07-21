//go:build darwin

package route

import (
	"net/netip"
	"testing"
)

// Regression for #129: while the tunnel's split-default (0/1, 128.0/1) is
// installed, parseDefaultGateway must return the HOST gateway from the literal
// "default" row — not the tunnel next-hop a longest-prefix lookup would hit.
func TestParseDefaultGateway_IgnoresTunnelSplitRoutes(t *testing.T) {
	out := []byte(`Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGScg          en0
0/1                10.8.0.1           UGSc         utun4
128.0/1            10.8.0.1           UGSc         utun4
10.8.0.1           10.8.0.1           UH           utun4
127                127.0.0.1          UCS            lo0
`)
	gw, err := parseDefaultGateway(out)
	if err != nil {
		t.Fatalf("parseDefaultGateway: %v", err)
	}
	if want := netip.MustParseAddr("192.168.1.1"); gw != want {
		t.Errorf("gateway = %v, want %v (the host default, not the tunnel 10.8.0.1)", gw, want)
	}
}

// A default via an interface (link#N) has no IP next-hop and is skipped; a
// later IP default is used instead.
func TestParseDefaultGateway_SkipsLinkDefaultForIPOne(t *testing.T) {
	out := []byte(`Destination        Gateway            Flags        Netif Expire
default            link#5             UCSI         utun3
default            10.0.0.1           UGScg          en0
`)
	gw, err := parseDefaultGateway(out)
	if err != nil {
		t.Fatalf("parseDefaultGateway: %v", err)
	}
	if want := netip.MustParseAddr("10.0.0.1"); gw != want {
		t.Errorf("gateway = %v, want %v", gw, want)
	}
}

// No default route at all → an error, not a silent zero Addr.
func TestParseDefaultGateway_NoDefaultRoute(t *testing.T) {
	out := []byte(`Destination        Gateway            Flags        Netif Expire
10.8.0.1           10.8.0.1           UH           utun4
`)
	if _, err := parseDefaultGateway(out); err == nil {
		t.Fatal("want an error when there is no default route")
	}
}
