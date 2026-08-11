package watchdog

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// recorder collects what the operator would have received.
type recorder struct {
	mu   sync.Mutex
	sent []string
}

func (r *recorder) notify(msg string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, msg)
}

func (r *recorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.sent...)
}

func newTestWatcher(t *testing.T, rec *recorder, tweak func(*Config)) *Watcher {
	t.Helper()
	cfg := Config{
		URL:                 "http://127.0.0.1:1/readyz",
		Notify:              rec.notify,
		FailuresBeforeAlert: 3,
	}
	if tweak != nil {
		tweak(&cfg)
	}
	w, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return w
}

func healthy() Observation    { return Observation{Report: Report{Live: true, Ready: true, Sessions: 2}} }
func unreadable() Observation { return Observation{Err: errors.New("connection refused")} }
func notReady(reason string) Observation {
	return Observation{Report: Report{Live: true, Ready: false, NotReady: []string{reason}}}
}

func TestAlertsOnlyAfterConsecutiveFailures(t *testing.T) {
	rec := &recorder{}
	w := newTestWatcher(t, rec, nil)

	w.Observe(unreadable())
	w.Observe(unreadable())
	if got := rec.all(); len(got) != 0 {
		t.Fatalf("alerted after 2 failures (threshold 3): %v", got)
	}
	w.Observe(unreadable())
	got := rec.all()
	if len(got) != 1 {
		t.Fatalf("want exactly 1 alert at the threshold, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "connection refused") {
		t.Errorf("alert does not say what went wrong: %s", got[0])
	}
}

// A node that stays down must not keep talking. This is the rule that decides
// whether the operator still reads these messages in a month.
func TestDoesNotRepeatWhileStillDown(t *testing.T) {
	rec := &recorder{}
	w := newTestWatcher(t, rec, nil)
	for range 20 {
		w.Observe(notReady("server certificate expired on 2026-08-01"))
	}
	if got := rec.all(); len(got) != 1 {
		t.Fatalf("want 1 alert for a continuous outage, got %d: %v", len(got), got)
	}
}

func TestSendsRecovery(t *testing.T) {
	rec := &recorder{}
	w := newTestWatcher(t, rec, nil)
	for range 3 {
		w.Observe(unreadable())
	}
	w.Observe(healthy())

	got := rec.all()
	if len(got) != 2 {
		t.Fatalf("want alert + recovery, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[1], "back") {
		t.Errorf("second message is not a recovery: %s", got[1])
	}

	// And the cycle can repeat: a second outage alerts again.
	for range 3 {
		w.Observe(unreadable())
	}
	if got := rec.all(); len(got) != 3 {
		t.Fatalf("second outage did not alert: %v", got)
	}
}

// A blip below the threshold must reset the counter, or a node that fails one
// poll a day would eventually "accumulate" its way to a false alarm.
func TestFailureRunResetsOnSuccess(t *testing.T) {
	rec := &recorder{}
	w := newTestWatcher(t, rec, nil)
	w.Observe(unreadable())
	w.Observe(unreadable())
	w.Observe(healthy())
	w.Observe(unreadable())
	w.Observe(unreadable())
	if got := rec.all(); len(got) != 0 {
		t.Fatalf("alerted on two separate 2-failure runs: %v", got)
	}
}

// A healthy node that never recovered was never alerted about — no recovery
// message should appear out of nowhere.
func TestNoRecoveryWithoutAlert(t *testing.T) {
	rec := &recorder{}
	w := newTestWatcher(t, rec, nil)
	w.Observe(healthy())
	w.Observe(unreadable())
	w.Observe(healthy())
	if got := rec.all(); len(got) != 0 {
		t.Fatalf("sent something without an outage: %v", got)
	}
}

func TestWarningsAreRateLimitedAndRefreshed(t *testing.T) {
	rec := &recorder{}
	clock := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	w := newTestWatcher(t, rec, func(c *Config) {
		c.WarningRepeat = 24 * time.Hour
		c.Now = func() time.Time { return clock }
	})
	warn := func(text string) Observation {
		return Observation{Report: Report{Live: true, Ready: true, Warnings: []string{text}}}
	}

	w.Observe(warn("certificate expires in 20 day(s)"))
	w.Observe(warn("certificate expires in 20 day(s)"))
	if got := rec.all(); len(got) != 1 {
		t.Fatalf("warning repeated within the window: %v", got)
	}
	// A day later the same warning is worth repeating.
	clock = clock.Add(25 * time.Hour)
	w.Observe(warn("certificate expires in 20 day(s)"))
	if got := rec.all(); len(got) != 2 {
		t.Fatalf("warning never repeated after the window: %v", got)
	}
	// A *different* warning is not suppressed by the previous one.
	w.Observe(warn("certificate expires in 3 day(s)"))
	got := rec.all()
	if len(got) != 3 {
		t.Fatalf("new warning text was suppressed: %v", got)
	}
	if !strings.Contains(got[2], "3 day") {
		t.Errorf("wrong warning delivered: %s", got[2])
	}
	// Once the warning clears, nothing more is sent about it.
	w.Observe(healthy())
	w.Observe(healthy())
	if len(rec.all()) != 3 {
		t.Errorf("sent something after the warning cleared: %v", rec.all())
	}
}

func TestPollReadsNotReadyBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 503 with a body is the endpoint working correctly, not a transport
		// error — the reasons live in the body.
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"live":true,"ready":false,"notReady":["revocation list cannot be read"]}`))
	}))
	defer srv.Close()

	rec := &recorder{}
	w := newTestWatcher(t, rec, func(c *Config) { c.URL = srv.URL + "/readyz" })
	obs := w.poll(context.Background())
	if obs.Err != nil {
		t.Fatalf("poll on a 503 returned a transport error: %v", obs.Err)
	}
	if obs.Report.Ready {
		t.Error("poll reported ready from a 503")
	}
	if len(obs.Report.NotReady) != 1 {
		t.Fatalf("reasons not decoded: %+v", obs.Report)
	}
}

func TestPollRejectsNonHealthResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html>hello from someone else's server</html>"))
	}))
	defer srv.Close()

	rec := &recorder{}
	w := newTestWatcher(t, rec, func(c *Config) { c.URL = srv.URL })
	if obs := w.poll(context.Background()); obs.Err == nil {
		t.Fatal("poll accepted a non-health response as healthy")
	}
}

func TestRunPollsImmediatelyAndStops(t *testing.T) {
	var hits int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"live":true,"ready":false,"notReady":["down"]}`))
	}))
	defer srv.Close()

	rec := &recorder{}
	w := newTestWatcher(t, rec, func(c *Config) {
		c.URL = srv.URL + "/readyz"
		c.Interval = 5 * time.Millisecond
		c.FailuresBeforeAlert = 1
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); w.Run(ctx) }()

	deadline := time.After(2 * time.Second)
	for len(rec.all()) == 0 {
		select {
		case <-deadline:
			cancel()
			t.Fatal("Run never alerted on a node that was down from the first poll")
		case <-time.After(2 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after its context was cancelled")
	}
	mu.Lock()
	defer mu.Unlock()
	if hits == 0 {
		t.Fatal("Run never polled")
	}
}

func TestNewRejectsUselessConfig(t *testing.T) {
	if _, err := New(Config{Notify: func(string) {}}); err == nil {
		t.Error("New accepted a config with no URL")
	}
	if _, err := New(Config{URL: "http://x/readyz"}); err == nil {
		t.Error("New accepted a watchdog with nobody to notify")
	}
}
