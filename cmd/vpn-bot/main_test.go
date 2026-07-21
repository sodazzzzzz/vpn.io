package main

import (
	"testing"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

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
