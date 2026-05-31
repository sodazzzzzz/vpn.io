package server

import (
	"context"
	"crypto/tls"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// recordingHandler is a thread-safe slog.Handler that keeps every record so a
// test can assert on the structured audit fields the server emits.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

// WithAttrs/WithGroup return the same handler: the audit helpers log their
// fields directly on each call, so the tests never rely on inherited attrs.
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

// waitForEvent polls up to d for the first record whose "event" attribute
// equals event, returning its attributes as a map. Polling absorbs the small
// races between client-visible progress and the server-side log call.
func (h *recordingHandler) waitForEvent(event string, d time.Duration) (map[string]string, bool) {
	deadline := time.Now().Add(d)
	for {
		h.mu.Lock()
		for _, r := range h.records {
			attrs := map[string]string{}
			r.Attrs(func(a slog.Attr) bool {
				attrs[a.Key] = a.Value.String()
				return true
			})
			if attrs[auditEventKey] == event {
				h.mu.Unlock()
				return attrs, true
			}
		}
		h.mu.Unlock()
		if time.Now().After(deadline) {
			return nil, false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestServer_AuditConnectDisconnect(t *testing.T) {
	h := startServer(t, "10.8.0.0/24", "10.8.0.1", "255.255.255.0")
	defer h.shutdown()

	cert := h.issueClient("alice")
	conn, err := h.dial([]tls.Certificate{cert})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	tunIP := h.expectAssignIP(conn)

	connect, ok := h.logs.waitForEvent("connect", 2*time.Second)
	if !ok {
		t.Fatal("no connect audit event logged")
	}
	if connect["cn"] != "alice" {
		t.Errorf("connect cn = %q, want alice", connect["cn"])
	}
	if connect["tun_ip"] != tunIP {
		t.Errorf("connect tun_ip = %q, want %q", connect["tun_ip"], tunIP)
	}
	if connect["remote"] == "" {
		t.Error("connect event has empty remote address")
	}

	// Closing the client connection makes the server's reader return and the
	// disconnect event fire.
	_ = conn.Close()

	disc, ok := h.logs.waitForEvent("disconnect", 2*time.Second)
	if !ok {
		t.Fatal("no disconnect audit event logged after client closed")
	}
	if disc["cn"] != "alice" {
		t.Errorf("disconnect cn = %q, want alice", disc["cn"])
	}
	if disc["tun_ip"] != tunIP {
		t.Errorf("disconnect tun_ip = %q, want %q", disc["tun_ip"], tunIP)
	}
	if disc["duration"] == "" {
		t.Error("disconnect event has no session duration")
	}
}

func TestServer_AuditKick(t *testing.T) {
	h := startServer(t, "10.8.0.0/24", "10.8.0.1", "255.255.255.0")
	defer h.shutdown()

	cert := h.issueClient("alice")

	first, err := h.dial([]tls.Certificate{cert})
	if err != nil {
		t.Fatalf("dial first: %v", err)
	}
	defer first.Close()
	h.expectAssignIP(first)

	// Same CN reconnecting kicks the first session.
	second, err := h.dial([]tls.Certificate{cert})
	if err != nil {
		t.Fatalf("dial second: %v", err)
	}
	defer second.Close()
	h.expectAssignIP(second)

	kick, ok := h.logs.waitForEvent("kick", 2*time.Second)
	if !ok {
		t.Fatal("no kick audit event logged on same-CN reconnect")
	}
	if kick["cn"] != "alice" {
		t.Errorf("kick cn = %q, want alice", kick["cn"])
	}
	if kick["by_remote"] == "" {
		t.Error("kick event has empty by_remote (the reconnecting client)")
	}
}
