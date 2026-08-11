// Package watchdog polls a vpn-server health endpoint and tells the operator
// when the answer changes.
//
// The node already knows when it is broken — /readyz says so in plain words.
// What was missing is anyone hearing it: an expired certificate or an
// unreadable deny-list turns every connection away silently, and the first
// report arrives as "the VPN stopped working" from a friend, hours later.
//
// Three rules shape everything here, and they all come from the same place —
// an alert nobody trusts is worse than no alert:
//
//   - Alert on CHANGE, not on state. A node that is down stays down; saying so
//     every minute trains the operator to swipe the notification away.
//   - Do not cry on the first miss. A single failed poll is usually a restart or
//     a dropped packet, so a run of consecutive failures is required before
//     anything is sent.
//   - Always send the recovery. An alert with no "it is back" leaves the
//     operator unable to tell a fixed problem from an ignored one.
package watchdog

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Defaults for the knobs a caller does not set.
const (
	DefaultInterval = time.Minute
	DefaultTimeout  = 10 * time.Second
	// DefaultFailuresBeforeAlert is how many consecutive bad polls it takes to
	// raise an alert. Three at the default interval means roughly three minutes
	// of genuine trouble, which is past every restart and blip this project
	// produces on its own — vpn-server's own restart takes about a second.
	DefaultFailuresBeforeAlert = 3
	// DefaultWarningRepeat bounds how often a non-fatal warning (the
	// certificate approaching expiry) is repeated while it persists.
	DefaultWarningRepeat = 24 * time.Hour
	// maxBodyBytes caps what is read from the endpoint. It is localhost and
	// ours, but a watchdog that can be made to allocate without limit is a
	// strange thing to run forever.
	maxBodyBytes = 64 << 10
)

// Report is the health document, kept as its own type rather than imported from
// the server package: this is a wire format crossing a process boundary, and the
// bot has no business pulling in the TUN device and the tunnel with it.
type Report struct {
	Live              bool     `json:"live"`
	Ready             bool     `json:"ready"`
	NotReady          []string `json:"notReady"`
	Warnings          []string `json:"warnings"`
	Sessions          int      `json:"sessions"`
	CertExpiresInDays int      `json:"certExpiresInDays"`
}

// Config describes what to watch and how to speak up.
type Config struct {
	// URL of the readiness endpoint, e.g. "http://127.0.0.1:9443/readyz".
	URL string
	// Interval between polls. 0 → DefaultInterval.
	Interval time.Duration
	// Timeout for a single poll. 0 → DefaultTimeout.
	Timeout time.Duration
	// FailuresBeforeAlert is the run of consecutive bad polls needed before an
	// alert is sent. 0 → DefaultFailuresBeforeAlert. 1 alerts on the first one.
	FailuresBeforeAlert int
	// WarningRepeat bounds repeats of a persisting warning. 0 →
	// DefaultWarningRepeat.
	WarningRepeat time.Duration
	// Notify delivers one message to the operator. Required.
	Notify func(string)
	// Logf records what the watchdog is doing locally. Optional.
	Logf func(format string, args ...any)
	// Now is a clock seam for tests. Optional.
	Now func() time.Time
	// Client is the HTTP client used for polls. Optional.
	Client *http.Client
}

// Watcher holds the alerting state between polls.
type Watcher struct {
	cfg Config

	// failures counts consecutive bad polls; alerted records whether the
	// operator has already been told about the current run of them.
	failures int
	alerted  bool
	// lastWarning is the warning text last sent, with when — so a persisting
	// warning repeats on a schedule instead of every poll, and a *different*
	// warning is not suppressed by an older one.
	lastWarning   string
	lastWarningAt time.Time
}

// New validates cfg and applies defaults.
func New(cfg Config) (*Watcher, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("watchdog: no URL to watch")
	}
	if cfg.Notify == nil {
		return nil, fmt.Errorf("watchdog: no Notify function — a watchdog with nobody to tell is just load")
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	if cfg.FailuresBeforeAlert <= 0 {
		cfg.FailuresBeforeAlert = DefaultFailuresBeforeAlert
	}
	if cfg.WarningRepeat <= 0 {
		cfg.WarningRepeat = DefaultWarningRepeat
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: cfg.Timeout}
	}
	return &Watcher{cfg: cfg}, nil
}

// Run polls until ctx is cancelled. The first poll happens immediately, so a
// watchdog started next to a node that is already broken says so at once rather
// than one interval later.
func (w *Watcher) Run(ctx context.Context) {
	tick := time.NewTicker(w.cfg.Interval)
	defer tick.Stop()
	for {
		w.Observe(w.poll(ctx))
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Observation is the outcome of one poll: either a report, or the reason there
// isn't one.
type Observation struct {
	Report Report
	// Err is non-nil when the endpoint could not be reached or understood.
	// That is treated exactly like "not ready": from the operator's chair,
	// a node that cannot say it is fine is not fine.
	Err error
}

// Observe folds one observation into the alerting state, sending at most one
// message. It is separate from polling so the decision logic can be tested
// without a network.
func (w *Watcher) Observe(obs Observation) {
	bad, reason := classify(obs)
	if bad {
		w.failures++
		w.cfg.Logf("watchdog: bad poll %d/%d: %s", w.failures, w.cfg.FailuresBeforeAlert, reason)
		if !w.alerted && w.failures >= w.cfg.FailuresBeforeAlert {
			w.alerted = true
			w.cfg.Notify(fmt.Sprintf("🔴 vpn-server is not serving clients.\n\n%s\n\n(%d checks in a row; watching %s)",
				reason, w.failures, w.cfg.URL))
		}
		return
	}

	if w.alerted {
		w.alerted = false
		w.cfg.Notify(fmt.Sprintf("🟢 vpn-server is back — accepting clients again (%d session(s) connected).", obs.Report.Sessions))
	}
	w.failures = 0
	w.maybeWarn(obs.Report)
}

// maybeWarn forwards non-fatal warnings — today, a certificate approaching
// expiry. These are not outages, so they are rate-limited hard: the same text
// is repeated at most once per WarningRepeat, and a warning that goes away
// stops without an "all clear" nobody needs.
func (w *Watcher) maybeWarn(rep Report) {
	if len(rep.Warnings) == 0 {
		w.lastWarning = ""
		return
	}
	text := strings.Join(rep.Warnings, "\n")
	now := w.cfg.Now()
	if text == w.lastWarning && now.Sub(w.lastWarningAt) < w.cfg.WarningRepeat {
		return
	}
	w.lastWarning, w.lastWarningAt = text, now
	w.cfg.Notify("🟡 vpn-server needs attention soon.\n\n" + text)
}

// classify decides whether an observation counts as trouble, and says why in
// the words the operator will read.
func classify(obs Observation) (bad bool, reason string) {
	if obs.Err != nil {
		return true, "The node did not answer its health check: " + obs.Err.Error()
	}
	if !obs.Report.Ready {
		if len(obs.Report.NotReady) > 0 {
			return true, strings.Join(obs.Report.NotReady, "\n")
		}
		return true, "The node reports it is not ready, without saying why."
	}
	return false, ""
}

// poll fetches and decodes the endpoint. A 503 is not an error: that is the
// endpoint working correctly and saying "not ready", and its body carries the
// reasons — which is the whole point of reading it rather than just the code.
func (w *Watcher) poll(ctx context.Context) Observation {
	ctx, cancel := context.WithTimeout(ctx, w.cfg.Timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.cfg.URL, nil)
	if err != nil {
		return Observation{Err: err}
	}
	resp, err := w.cfg.Client.Do(req)
	if err != nil {
		return Observation{Err: err}
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return Observation{Err: fmt.Errorf("read response: %w", err)}
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
		return Observation{Err: fmt.Errorf("unexpected status %s from %s", resp.Status, w.cfg.URL)}
	}
	var rep Report
	if err := json.Unmarshal(body, &rep); err != nil {
		return Observation{Err: fmt.Errorf("health endpoint returned something that is not a health report: %w", err)}
	}
	return Observation{Report: rep}
}
