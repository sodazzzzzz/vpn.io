package main

import (
	"strings"
	"testing"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"

	"github.com/govpn/internal/invite"
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
		{Value: "SECRET-ALICE", ClientName: "alice", Created: now.Add(-10 * time.Minute)},
		{Value: "SECRET-BOB", ClientName: "bob", Used: true, UsedBy: "carol (id 7)", UsedAt: now, Created: now.Add(-2 * time.Hour)},
		{Value: "SECRET-DAVE", ClientName: "dave", Created: now.Add(-2 * time.Hour)}, // past ttl → EXPIRED
	}
	got := formatInviteList(tokens, ttl, now)

	for _, secret := range []string{"SECRET-ALICE", "SECRET-BOB", "SECRET-DAVE"} {
		if strings.Contains(got, secret) {
			t.Fatalf("output leaked a token value %q:\n%s", secret, got)
		}
	}
	for _, want := range []string{"Issued invites (3)", "alice — PENDING", "bob — used by carol (id 7)", "dave — EXPIRED"} {
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
