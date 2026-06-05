package route

import (
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"reflect"
	"testing"
)

type call struct {
	op     string // "add" or "del"
	prefix netip.Prefix
	gw     netip.Addr
	iface  string
}

type mockRunner struct {
	defaultGW netip.Addr
	defaultGWErr,
	addErr,
	delErr error
	calls []call
}

func (m *mockRunner) DefaultGateway() (netip.Addr, error) {
	return m.defaultGW, m.defaultGWErr
}

func (m *mockRunner) AddRoute(p netip.Prefix, gw netip.Addr, iface string) error {
	m.calls = append(m.calls, call{op: "add", prefix: p, gw: gw, iface: iface})
	return m.addErr
}

func (m *mockRunner) DelRoute(p netip.Prefix, gw netip.Addr, iface string) error {
	m.calls = append(m.calls, call{op: "del", prefix: p, gw: gw, iface: iface})
	return m.delErr
}

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestInstall_FullTunnel_SplitsDefault(t *testing.T) {
	r := &mockRunner{defaultGW: netip.MustParseAddr("192.168.1.1")}
	m := newWithRunner(discard(), "utun4",
		netip.MustParseAddr("10.8.0.1"),
		netip.MustParseAddr("203.0.113.5"),
		r,
	)
	if err := m.Install([]string{"0.0.0.0/0"}); err != nil {
		t.Fatalf("Install: %v", err)
	}

	want := []call{
		{op: "add", prefix: netip.MustParsePrefix("203.0.113.5/32"), gw: netip.MustParseAddr("192.168.1.1"), iface: ""},
		{op: "add", prefix: netip.MustParsePrefix("0.0.0.0/1"), gw: netip.MustParseAddr("10.8.0.1"), iface: "utun4"},
		{op: "add", prefix: netip.MustParsePrefix("128.0.0.0/1"), gw: netip.MustParseAddr("10.8.0.1"), iface: "utun4"},
	}
	if !reflect.DeepEqual(r.calls, want) {
		t.Fatalf("calls mismatch:\n got=%+v\nwant=%+v", r.calls, want)
	}
}

func TestInstall_SpecificRoutes_NoSplit(t *testing.T) {
	r := &mockRunner{defaultGW: netip.MustParseAddr("192.168.1.1")}
	m := newWithRunner(discard(), "utun4",
		netip.MustParseAddr("10.8.0.1"),
		netip.MustParseAddr("203.0.113.5"),
		r,
	)
	if err := m.Install([]string{"10.0.0.0/8", "192.168.42.0/24"}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	want := []call{
		{op: "add", prefix: netip.MustParsePrefix("203.0.113.5/32"), gw: netip.MustParseAddr("192.168.1.1"), iface: ""},
		{op: "add", prefix: netip.MustParsePrefix("10.0.0.0/8"), gw: netip.MustParseAddr("10.8.0.1"), iface: "utun4"},
		{op: "add", prefix: netip.MustParsePrefix("192.168.42.0/24"), gw: netip.MustParseAddr("10.8.0.1"), iface: "utun4"},
	}
	if !reflect.DeepEqual(r.calls, want) {
		t.Fatalf("calls mismatch:\n got=%+v\nwant=%+v", r.calls, want)
	}
}

func TestRemove_ReverseOrder(t *testing.T) {
	r := &mockRunner{defaultGW: netip.MustParseAddr("192.168.1.1")}
	m := newWithRunner(discard(), "utun4",
		netip.MustParseAddr("10.8.0.1"),
		netip.MustParseAddr("203.0.113.5"),
		r,
	)
	if err := m.Install([]string{"0.0.0.0/0"}); err != nil {
		t.Fatalf("Install: %v", err)
	}
	r.calls = nil // clear adds
	m.Remove()

	want := []call{
		{op: "del", prefix: netip.MustParsePrefix("128.0.0.0/1"), gw: netip.MustParseAddr("10.8.0.1"), iface: "utun4"},
		{op: "del", prefix: netip.MustParsePrefix("0.0.0.0/1"), gw: netip.MustParseAddr("10.8.0.1"), iface: "utun4"},
		{op: "del", prefix: netip.MustParsePrefix("203.0.113.5/32"), gw: netip.MustParseAddr("192.168.1.1"), iface: "utun4"},
	}
	if !reflect.DeepEqual(r.calls, want) {
		t.Fatalf("calls mismatch:\n got=%+v\nwant=%+v", r.calls, want)
	}
}

func TestInstall_RollsBackOnFailure(t *testing.T) {
	// Configure AddRoute to succeed for the pin-hole then fail for the
	// pushed route — Install must roll back the pin-hole.
	r := &mockRunner{defaultGW: netip.MustParseAddr("192.168.1.1")}
	addCallCount := 0
	r.addErr = nil
	addOrig := r.AddRoute
	_ = addOrig
	// Wrap by replacing the AddRoute logic via a thin shim around the mock.
	r2 := &countingRunner{
		base: r,
		failAddOnCall: func(n int) bool {
			addCallCount++
			return addCallCount == 2 // fail the first pushed route
		},
	}
	m := newWithRunner(discard(), "utun4",
		netip.MustParseAddr("10.8.0.1"),
		netip.MustParseAddr("203.0.113.5"),
		r2,
	)
	err := m.Install([]string{"10.0.0.0/8"})
	if err == nil {
		t.Fatal("expected Install to fail")
	}

	// We expect: add pin-hole (ok), try add 10/8 (fail), del pin-hole (rollback).
	want := []call{
		{op: "add", prefix: netip.MustParsePrefix("203.0.113.5/32"), gw: netip.MustParseAddr("192.168.1.1"), iface: ""},
		{op: "add", prefix: netip.MustParsePrefix("10.0.0.0/8"), gw: netip.MustParseAddr("10.8.0.1"), iface: "utun4"},
		{op: "del", prefix: netip.MustParsePrefix("203.0.113.5/32"), gw: netip.MustParseAddr("192.168.1.1"), iface: "utun4"},
	}
	if !reflect.DeepEqual(r.calls, want) {
		t.Fatalf("calls mismatch:\n got=%+v\nwant=%+v", r.calls, want)
	}
}

// countingRunner is a tiny wrapper that lets a test fail a specific Add call.
type countingRunner struct {
	base          *mockRunner
	failAddOnCall func(n int) bool
}

func (c *countingRunner) DefaultGateway() (netip.Addr, error) {
	return c.base.DefaultGateway()
}

func (c *countingRunner) AddRoute(p netip.Prefix, gw netip.Addr, iface string) error {
	c.base.calls = append(c.base.calls, call{op: "add", prefix: p, gw: gw, iface: iface})
	if c.failAddOnCall != nil && c.failAddOnCall(len(c.base.calls)) {
		return errors.New("boom")
	}
	return nil
}

func (c *countingRunner) DelRoute(p netip.Prefix, gw netip.Addr, iface string) error {
	c.base.calls = append(c.base.calls, call{op: "del", prefix: p, gw: gw, iface: iface})
	return nil
}

func TestInstall_BadCIDR(t *testing.T) {
	r := &mockRunner{defaultGW: netip.MustParseAddr("192.168.1.1")}
	m := newWithRunner(discard(), "utun4",
		netip.MustParseAddr("10.8.0.1"),
		netip.MustParseAddr("203.0.113.5"),
		r,
	)
	err := m.Install([]string{"not-a-cidr"})
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
	// Pin-hole should still be rolled back.
	hasDel := false
	for _, c := range r.calls {
		if c.op == "del" {
			hasDel = true
		}
	}
	if !hasDel {
		t.Fatalf("expected rollback after bad CIDR, got calls: %+v", r.calls)
	}
}

func TestInstall_DefaultGatewayError(t *testing.T) {
	r := &mockRunner{defaultGWErr: errors.New("nope")}
	m := newWithRunner(discard(), "utun4",
		netip.MustParseAddr("10.8.0.1"),
		netip.MustParseAddr("203.0.113.5"),
		r,
	)
	if err := m.Install([]string{"0.0.0.0/0"}); err == nil {
		t.Fatal("expected Install to error when DefaultGateway fails")
	}
	if len(r.calls) != 0 {
		t.Fatalf("no routes should be added when default gw lookup fails, got %+v", r.calls)
	}
}

func TestRefreshServerPinhole_RepinsViaNewGateway(t *testing.T) {
	r := &mockRunner{defaultGW: netip.MustParseAddr("192.168.1.1")}
	m := newWithRunner(discard(), "utun4",
		netip.MustParseAddr("10.8.0.1"),
		netip.MustParseAddr("203.0.113.5"),
		r,
	)
	if err := m.Install([]string{"0.0.0.0/0"}); err != nil {
		t.Fatalf("Install: %v", err)
	}

	// Simulate a network change: the default gateway moved after a Wi-Fi rejoin.
	r.defaultGW = netip.MustParseAddr("10.0.0.1")
	r.calls = nil
	if err := m.RefreshServerPinhole(); err != nil {
		t.Fatalf("RefreshServerPinhole: %v", err)
	}

	pinhole := netip.MustParsePrefix("203.0.113.5/32")
	want := []call{
		{op: "del", prefix: pinhole, gw: netip.MustParseAddr("192.168.1.1"), iface: ""},
		{op: "add", prefix: pinhole, gw: netip.MustParseAddr("10.0.0.1"), iface: ""},
	}
	if !reflect.DeepEqual(r.calls, want) {
		t.Fatalf("calls mismatch:\n got=%+v\nwant=%+v", r.calls, want)
	}

	// Rollback must now target the live pin-hole (refreshed gateway), so the
	// shutdown delete doesn't leave a stale host route behind.
	r.calls = nil
	m.Remove()
	last := r.calls[len(r.calls)-1]
	if last.op != "del" || last.prefix != pinhole || last.gw != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("pin-hole rollback used wrong gateway: %+v", last)
	}
}

func TestRefreshServerPinhole_GatewayErrorReportedNoChange(t *testing.T) {
	r := &mockRunner{defaultGW: netip.MustParseAddr("192.168.1.1")}
	m := newWithRunner(discard(), "utun4",
		netip.MustParseAddr("10.8.0.1"),
		netip.MustParseAddr("203.0.113.5"),
		r,
	)
	if err := m.Install([]string{"0.0.0.0/0"}); err != nil {
		t.Fatalf("Install: %v", err)
	}

	// Network still down on reconnect: DefaultGateway fails → refresh returns an
	// error and touches no routes (caller falls through to a normal retry).
	r.defaultGW = netip.Addr{}
	r.defaultGWErr = errors.New("no default route")
	r.calls = nil
	if err := m.RefreshServerPinhole(); err == nil {
		t.Fatal("expected an error when the default gateway is unavailable")
	}
	if len(r.calls) != 0 {
		t.Fatalf("expected no route calls on gateway error, got %+v", r.calls)
	}
}

func TestRefreshServerPinhole_SkipsWhenGatewayResolvesToTunnel(t *testing.T) {
	r := &mockRunner{defaultGW: netip.MustParseAddr("192.168.1.1")}
	m := newWithRunner(discard(), "utun4",
		netip.MustParseAddr("10.8.0.1"),
		netip.MustParseAddr("203.0.113.5"),
		r,
	)
	if err := m.Install([]string{"0.0.0.0/0"}); err != nil {
		t.Fatalf("Install: %v", err)
	}

	// On a reconnect the OS default-route lookup can hand back the tunnel gateway
	// (the split-routes point there). Refresh must skip rather than pin the server
	// through the tunnel it carries.
	r.defaultGW = netip.MustParseAddr("10.8.0.1") // == tunnel gateway
	r.calls = nil
	if err := m.RefreshServerPinhole(); err == nil {
		t.Fatal("expected refresh to skip when the gateway resolves to the tunnel")
	}
	if len(r.calls) != 0 {
		t.Fatalf("expected no route calls when gateway is the tunnel, got %+v", r.calls)
	}
}
