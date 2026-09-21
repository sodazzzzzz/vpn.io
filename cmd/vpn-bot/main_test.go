package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"github.com/govpn/internal/invite"
	"github.com/govpn/internal/vless"
)

// formatInviteList must never echo a token secret, and must label each token's
// state (PENDING / EXPIRED / used-by-whom) for the owner's /invites (#108).
func TestFormatInviteList(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	ttl := time.Hour

	if got := formatInviteList(nil, ttl, now); !strings.Contains(got, "No invites") {
		t.Fatalf("empty list = %q", got)
	}

	tokens := []invite.Token{
		// No grant: a token minted before grants existed, shown as what it has
		// always meant.
		{Value: "SECRET-ALICE", ClientName: "alice", Created: now.Add(-10 * time.Minute)},
		{Value: "SECRET-BOB", ClientName: "bob", Grant: invite.GrantVLESS, Used: true, UsedBy: "carol (id 7)", UsedAt: now, Created: now.Add(-2 * time.Hour)},
		{Value: "SECRET-DAVE", ClientName: "dave", Grant: invite.GrantBoth, Created: now.Add(-2 * time.Hour)}, // past ttl → EXPIRED
	}
	got := formatInviteList(tokens, ttl, now)

	for _, secret := range []string{"SECRET-ALICE", "SECRET-BOB", "SECRET-DAVE"} {
		if strings.Contains(got, secret) {
			t.Fatalf("output leaked a token value %q:\n%s", secret, got)
		}
	}
	// The grant is part of the line: the owner reading this list needs to know
	// what each invite hands over, not just to whom.
	for _, want := range []string{
		"Issued invites (3)",
		"alice [profile] — PENDING",
		"bob [vless] — used by carol (id 7)",
		"dave [both] — EXPIRED",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

// Redeeming a token replies with a .vpnio bundle containing the client's
// private key, so it must be confined to private chats: a token pasted into a
// group would otherwise hand every member a working profile.
func TestRedeemableChatOnlyPrivate(t *testing.T) {
	tests := []struct {
		chatType string
		want     bool
	}{
		{"private", true},
		{"group", false},
		{"supergroup", false},
		{"channel", false},
	}
	for _, tt := range tests {
		if got := redeemableChat(&tgbotapi.Chat{Type: tt.chatType}); got != tt.want {
			t.Errorf("redeemableChat(%q) = %v, want %v", tt.chatType, got, tt.want)
		}
	}
	if redeemableChat(nil) {
		t.Error("redeemableChat(nil) = true, want false")
	}
}

// The owner chooses what an invite hands over when they mint it. Parsing that
// choice is the only place a typo can quietly turn "both" into "profile", so
// check the shapes /invite actually receives.
func TestInviteGrantArgument(t *testing.T) {
	tests := []struct {
		args      string
		wantName  string
		wantGrant invite.Grant
	}{
		{"anna", "anna", invite.GrantProfile},
		{"anna vless", "anna", invite.GrantVLESS},
		{"anna both", "anna", invite.GrantBoth},
		{"  anna   BOTH  ", "anna", invite.GrantBoth},
	}
	for _, tt := range tests {
		name, grantRaw, _ := strings.Cut(strings.TrimSpace(tt.args), " ")
		name = strings.TrimSpace(name)
		grant, err := invite.ParseGrant(grantRaw)
		if err != nil {
			t.Fatalf("ParseGrant(%q): %v", tt.args, err)
		}
		if name != tt.wantName || grant != tt.wantGrant {
			t.Errorf("/invite %q → name %q grant %q, want %q / %q", tt.args, name, grant, tt.wantName, tt.wantGrant)
		}
	}
}

// testEnv builds an env whose VLESS half is real (a store in a temp dir) but
// whose systemd is not: applied decides what confirming a change reports.
func testEnv(t *testing.T, applied error) *env {
	t.Helper()
	store := vless.New(t.TempDir())
	node, err := vless.NewNode("203.0.113.10", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	if err := store.SaveNode(node); err != nil {
		t.Fatalf("SaveNode: %v", err)
	}
	return &env{
		vless:       store,
		vlessUnit:   vless.DefaultUnit,
		waitApplied: func(context.Context, string) error { return applied },
	}
}

// Revoking someone who has a link must remove it and say so — and the reply is
// the only place the owner learns whether it actually took effect.
func TestRevokeVLESS(t *testing.T) {
	e := testEnv(t, nil)
	if _, err := e.vless.Add("anna"); err != nil {
		t.Fatalf("Add: %v", err)
	}

	text, found := revokeVLESS(e, "anna", "tg:owner")
	if !found {
		t.Fatal("revokeVLESS did not find an existing client")
	}
	if !strings.Contains(text, "dead") {
		t.Errorf("reply does not say the link is dead: %q", text)
	}
	clients, err := e.vless.Clients()
	if err != nil {
		t.Fatalf("Clients: %v", err)
	}
	if len(clients) != 0 {
		t.Errorf("client list still has %d entries", len(clients))
	}
}

// Someone who only ever had an app profile is not a failure to report: /revoke
// covers both services and either half may be empty.
func TestRevokeVLESSUnknownName(t *testing.T) {
	e := testEnv(t, nil)
	if text, found := revokeVLESS(e, "nobody", "tg:owner"); found || text != "" {
		t.Errorf("revokeVLESS on an unknown name = %q, %v", text, found)
	}
}

// A node with no VLESS service must not claim to have revoked anything there.
func TestRevokeVLESSDisabled(t *testing.T) {
	e := &env{}
	if text, found := revokeVLESS(e, "anna", "tg:owner"); found || text != "" {
		t.Errorf("revokeVLESS with no service = %q, %v", text, found)
	}
}

// The dangerous direction: the name is off the list but the service never
// restarted, so the link still works. The owner must be told in plain words,
// not reassured.
func TestRevokeVLESSServiceDidNotRestart(t *testing.T) {
	e := testEnv(t, errors.New("unit failed"))
	if _, err := e.vless.Add("anna"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	text, found := revokeVLESS(e, "anna", "tg:owner")
	if !found {
		t.Fatal("revokeVLESS did not find an existing client")
	}
	if !strings.Contains(text, "may still work") {
		t.Errorf("reply hides that the link may still be live: %q", text)
	}
	if strings.Contains(text, "dead") {
		t.Errorf("reply claims the link is dead when the service never restarted: %q", text)
	}
}
