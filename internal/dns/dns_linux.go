//go:build linux

package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"time"
)

// resolvConfPath is the file rewritten on systems without systemd-resolved.
// It's a var so tests can point it at a temp file.
var resolvConfPath = "/etc/resolv.conf"

// commandTimeout bounds each external call (resolvectl talks to
// systemd-resolved over D-Bus, which can hang after suspend/resume).
const commandTimeout = 5 * time.Second

// newRunner returns the Linux Runner. It picks a mechanism at Apply time:
// systemd-resolved (resolvectl) when that's the active resolver, otherwise
// a backup-and-rewrite of /etc/resolv.conf.
func newRunner() Runner { return &linuxRunner{} }

type linuxRunner struct {
	// mode records which mechanism Apply used, so Restore can reverse it.
	mode  string // "" | "resolvectl" | "file"
	iface string // resolvectl link to revert

	// /etc/resolv.conf snapshot (mode == "file"):
	hadFile   bool   // a file/symlink existed before we touched it
	savedLink string // non-empty → original was a symlink to this target
	savedData []byte // original content when it was a regular file
}

func (r *linuxRunner) Apply(servers []string, iface string) error {
	// servers are already filtered to bare IPs by Manager.Apply (cross-platform).
	if useResolvectl() {
		return r.applyResolvectl(servers, iface)
	}
	return r.applyResolvConf(servers)
}

func (r *linuxRunner) Restore() error {
	switch r.mode {
	case "resolvectl":
		return run("resolvectl", "revert", r.iface)
	case "file":
		return r.restoreResolvConf()
	default:
		return nil
	}
}

// Clear recovers DNS without the in-process snapshot — the crash case. Only
// file-mode leaves anything durable to undo: /etc/resolv.conf is a plain file
// that outlives the process, whereas systemd-resolved's per-link config dies
// with the tunnel interface and needs no cleanup. So Clear restores from the
// on-disk backup written at Apply, if one is there. Best-effort: no backup
// means nothing of ours to undo.
func (r *linuxRunner) Clear(log *slog.Logger) error {
	restored, err := restoreResolvBackup()
	if err != nil {
		return err
	}
	if restored {
		log.Info("dns: restored /etc/resolv.conf from a prior run's backup")
	}
	return nil
}

// Reconcile is the same crash recovery, run at helper startup: the durable
// backup exists only if a previous run applied file-mode DNS and didn't clean
// up, so restoring it is always the right, non-destructive move.
func (r *linuxRunner) Reconcile(log *slog.Logger) error { return r.Clear(log) }

// useResolvectl reports whether systemd-resolved is the active resolver:
// the resolvectl binary is present and systemd-resolved's runtime dir
// exists (it's created only while the service runs).
func useResolvectl() bool {
	if _, err := exec.LookPath("resolvectl"); err != nil {
		return false
	}
	if _, err := os.Stat("/run/systemd/resolve"); err != nil {
		return false
	}
	return true
}

func (r *linuxRunner) applyResolvectl(servers []string, iface string) error {
	if iface == "" {
		return fmt.Errorf("resolvectl: empty interface")
	}
	if err := run("resolvectl", append([]string{"dns", iface}, servers...)...); err != nil {
		return err
	}
	// "~." makes this link the default route for every DNS query, so the
	// tunnel resolver wins over the host's existing ones. If this second
	// step fails the link already has our servers set, and the Manager
	// won't call Restore after a failed Apply — so revert here ourselves.
	if err := run("resolvectl", "domain", iface, "~."); err != nil {
		_ = run("resolvectl", "revert", iface)
		return err
	}
	r.mode = "resolvectl"
	r.iface = iface
	return nil
}

func (r *linuxRunner) applyResolvConf(servers []string) error {
	switch fi, err := os.Lstat(resolvConfPath); {
	case err == nil && fi.Mode()&os.ModeSymlink != 0:
		target, lerr := os.Readlink(resolvConfPath)
		if lerr != nil {
			return fmt.Errorf("read resolv.conf symlink: %w", lerr)
		}
		r.savedLink, r.hadFile = target, true
	case err == nil:
		data, rerr := os.ReadFile(resolvConfPath)
		if rerr != nil {
			return fmt.Errorf("read resolv.conf: %w", rerr)
		}
		r.savedData, r.hadFile = data, true
	case os.IsNotExist(err):
		r.hadFile = false
	default:
		return fmt.Errorf("stat resolv.conf: %w", err)
	}

	// Persist the original next to resolv.conf so a crash — which loses the
	// in-memory snapshot above — can still be undone by Clear/Reconcile. Best-
	// effort: a clean Restore uses the in-memory snapshot, so a failed backup
	// write only costs crash recovery, not correctness; don't fail Apply over it.
	_ = writeResolvBackup(resolvBackup{Existed: r.hadFile, Link: r.savedLink, Data: r.savedData})

	if err := writeFileAtomic(resolvConfPath, buildResolvConf(servers)); err != nil {
		return err
	}
	r.mode = "file"
	return nil
}

func (r *linuxRunner) restoreResolvConf() error {
	// A clean Restore makes the durable crash-backup obsolete — drop it so a
	// later helper start doesn't "recover" a resolv.conf we already put back.
	defer func() { _ = os.Remove(backupResolvConfPath()) }()
	if !r.hadFile {
		if err := os.Remove(resolvConfPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if r.savedLink != "" {
		return symlinkAtomic(r.savedLink, resolvConfPath)
	}
	return writeFileAtomic(resolvConfPath, r.savedData)
}

// resolvBackup is the durable snapshot of the original /etc/resolv.conf, written
// beside it at Apply so a crash-recovery Clear/Reconcile can put it back after
// the in-memory snapshot is gone. It mirrors the linuxRunner file-mode fields:
// Existed says a file/symlink was there before us; Link (when set) means it was
// a symlink to that target; Data holds the content when it was a regular file.
type resolvBackup struct {
	Existed bool   `json:"existed"`
	Link    string `json:"link,omitempty"`
	Data    []byte `json:"data,omitempty"`
}

// backupResolvConfPath tracks resolvConfPath (so tests that repoint that var
// exercise the real code) with a fixed, root-writable suffix that survives a
// crash.
func backupResolvConfPath() string { return resolvConfPath + ".vpnio-bak" }

func writeResolvBackup(b resolvBackup) error {
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}
	return writeFileAtomic(backupResolvConfPath(), data)
}

// restoreResolvBackup puts /etc/resolv.conf back to the durable snapshot and
// deletes the snapshot. It reports whether a snapshot was found (false = nothing
// of ours to undo).
func restoreResolvBackup() (restored bool, err error) {
	data, err := os.ReadFile(backupResolvConfPath())
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("read resolv.conf backup: %w", err)
	}
	var b resolvBackup
	if err := json.Unmarshal(data, &b); err != nil {
		return false, fmt.Errorf("parse resolv.conf backup: %w", err)
	}
	if err := applyResolvBackup(b); err != nil {
		return false, err
	}
	if err := os.Remove(backupResolvConfPath()); err != nil && !os.IsNotExist(err) {
		return true, err
	}
	return true, nil
}

// applyResolvBackup restores resolv.conf from a decoded backup: recreate the
// symlink, rewrite the file, or remove ours if none existed before.
func applyResolvBackup(b resolvBackup) error {
	if !b.Existed {
		if err := os.Remove(resolvConfPath); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	if b.Link != "" {
		return symlinkAtomic(b.Link, resolvConfPath)
	}
	return writeFileAtomic(resolvConfPath, b.Data)
}

// symlinkAtomic recreates a symlink at path atomically: it builds the link
// at a sibling temp name and renames it over path. A plain Remove+Symlink
// could leave path missing if Symlink failed (no inodes, full disk),
// breaking DNS with no resolv.conf at all; rename swaps it in or leaves the
// existing file untouched.
func symlinkAtomic(target, path string) error {
	tmp := path + ".vpnio.tmp"
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Symlink(target, tmp); err != nil {
		return fmt.Errorf("symlink %s -> %s: %w", tmp, target, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
	}
	return nil
}

// buildResolvConf renders the resolv.conf body for servers. Callers pass
// pre-validated IPs (Manager.Apply runs validIPs first). Pure, so it's
// unit-testable.
func buildResolvConf(servers []string) []byte {
	var b strings.Builder
	b.WriteString("# Managed by vpn.io while the tunnel is up\n")
	for _, s := range servers {
		fmt.Fprintf(&b, "nameserver %s\n", s)
	}
	return []byte(b.String())
}

// writeFileAtomic writes content to a sibling temp file and renames it over
// path. rename replaces the destination atomically — including a symlink,
// which it swaps for our regular file rather than following.
func writeFileAtomic(path string, content []byte) error {
	tmp := path + ".vpnio.tmp"
	// Drop any stale temp entry first: a leftover symlink here (e.g. from a
	// crashed symlinkAtomic) would make os.WriteFile follow it and clobber
	// the link target instead of creating our own regular file.
	if err := os.Remove(tmp); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.WriteFile(tmp, content, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
	}
	return nil
}

func run(name string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
