// vpn-ca manages the mTLS Certificate Authority for govpn.
//
// Typical workflow:
//
//	vpn-ca init
//	vpn-ca issue-server -hosts vpn.example.com,203.0.113.5
//	vpn-ca issue-client -name alice
//	vpn-ca list
package main

import (
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/govpn/internal/ca"
	"github.com/govpn/internal/profile"
	"github.com/govpn/internal/revoke"
)

const defaultDir = "./ca-data"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "issue-server":
		err = cmdIssueServer(os.Args[2:])
	case "issue-client":
		err = cmdIssueClient(os.Args[2:])
	case "list":
		err = cmdList(os.Args[2:])
	case "export-profile":
		err = cmdExportProfile(os.Args[2:])
	case "revoke":
		err = cmdRevoke(os.Args[2:])
	case "unrevoke":
		err = cmdUnrevoke(os.Args[2:])
	case "backup":
		err = cmdBackup(os.Args[2:])
	case "restore":
		err = cmdRestore(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `vpn-ca — manage the mTLS Certificate Authority for govpn.

Commands:
  init         [-dir DIR] [-cn NAME]                          create a fresh CA
  issue-server [-dir DIR] -hosts host1,host2,1.2.3.4 [-cn N]  issue the server cert
  issue-client [-dir DIR] -name NAME                          issue a client cert
  list         [-dir DIR]                                     list issued clients (and revoked)
  export-profile [-dir DIR] -name NAME -server HOST:PORT [-server-name S] [-out FILE]
                                                              bundle a client into one .vpnio file
  revoke       [-dir DIR] -name NAME                          revoke a client (server rejects it)
  unrevoke     [-dir DIR] -name NAME                          undo a revoke
  backup       [-dir DIR] [-out FILE] [-passphrase-file F]    encrypted backup of the whole CA
  restore      [-dir DIR] -in FILE [-passphrase-file F]       restore a CA from a backup

Default -dir is ./ca-data.

The backup passphrase is read from -passphrase-file (use "-" for stdin), or
from $VPNIO_CA_PASSPHRASE. It is never prompted for and never echoed, so both
commands work the same by hand and from a script:

  pass show vpnio/ca-backup | vpn-ca backup -passphrase-file -
`)
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", defaultDir, "directory to hold CA material")
	cn := fs.String("cn", "govpn CA", "CommonName for the CA certificate")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := ca.Create(*dir, *cn)
	if err != nil {
		return err
	}
	fmt.Printf("Created CA at %s\n  CN:    %s\n  valid: until %s\n",
		a.Dir, a.Cert.Subject.CommonName, a.Cert.NotAfter.Format("2006-01-02"))
	return nil
}

func cmdIssueServer(args []string) error {
	fs := flag.NewFlagSet("issue-server", flag.ExitOnError)
	dir := fs.String("dir", defaultDir, "CA directory")
	cn := fs.String("cn", "govpn server", "CommonName for the server certificate")
	hosts := fs.String("hosts", "", "comma-separated DNS names and IPs the server is reachable at (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *hosts == "" {
		return fmt.Errorf("-hosts is required (e.g. -hosts vpn.example.com,203.0.113.5)")
	}
	a, err := ca.Load(*dir)
	if err != nil {
		return err
	}
	dns, ips := splitHosts(*hosts)
	if err := a.IssueServer(*cn, dns, ips); err != nil {
		return err
	}
	fmt.Printf("Issued server cert\n  CN:   %s\n  DNS:  %v\n  IPs:  %v\n", *cn, dns, ips)
	return nil
}

func cmdIssueClient(args []string) error {
	fs := flag.NewFlagSet("issue-client", flag.ExitOnError)
	dir := fs.String("dir", defaultDir, "CA directory")
	name := fs.String("name", "", "client name; used as CommonName and filename (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("-name is required")
	}
	a, err := ca.Load(*dir)
	if err != nil {
		return err
	}
	if err := a.IssueClient(*name); err != nil {
		return err
	}
	fmt.Printf("Issued client cert for %q\n", *name)
	return nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	dir := fs.String("dir", defaultDir, "CA directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := ca.Load(*dir)
	if err != nil {
		return err
	}
	fmt.Printf("CA:     %s (valid until %s)\n",
		a.Cert.Subject.CommonName, a.Cert.NotAfter.Format("2006-01-02"))
	clients, err := a.ListClients()
	if err != nil {
		return err
	}
	if len(clients) == 0 {
		fmt.Println("Clients: (none issued)")
	} else {
		fmt.Println("Clients:")
		for _, c := range clients {
			fmt.Printf("  - %s\n", c)
		}
	}
	revs, err := revoke.New(filepath.Join(*dir, "revoked.json")).List()
	if err != nil {
		return err
	}
	if len(revs) > 0 {
		fmt.Println("Revoked:")
		for _, r := range revs {
			fmt.Printf("  - %s (serial %s, %s)\n", r.Name, r.Serial, r.RevokedAt.Format("2006-01-02"))
		}
	}
	return nil
}

// cmdRevoke revokes every certificate ever issued to a client: the server
// rejects them on the next connection (it hot-reloads the deny-list), no
// restart needed. Revoking by name rather than by the current certificate is
// what makes a re-issued (superseded) certificate reachable at all — its serial
// is no longer in clients/<name>.crt, only in the issuance ledger.
func cmdRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	dir := fs.String("dir", defaultDir, "CA directory")
	name := fs.String("name", "", "client name to revoke (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("-name is required")
	}
	if strings.ContainsAny(*name, `/\`) || *name == "." || *name == ".." {
		return fmt.Errorf("-name must be a plain client name (no path separators)")
	}
	serials, err := ca.ClientSerials(*dir, *name)
	if err != nil {
		return err
	}
	store := revoke.New(filepath.Join(*dir, "revoked.json"))
	added := 0
	for _, serial := range serials {
		ok, err := store.Add(serial, *name)
		if err != nil {
			return err
		}
		if ok {
			added++
		}
	}
	switch {
	case added == 0:
		fmt.Printf("%q was already revoked (%d certificate(s)).\n", *name, len(serials))
	case len(serials) == 1:
		fmt.Printf("Revoked %q (serial %s). The server rejects it on the next connection.\n", *name, serials[0].Text(16))
	default:
		fmt.Printf("Revoked %q — %d certificate(s), %d newly. The server rejects them on the next connection.\n",
			*name, len(serials), added)
	}
	return nil
}

// cmdUnrevoke undoes a revoke for the client's *current* certificate. It
// deliberately does not lift revocations on superseded certificates — those
// were retired by a re-issue, and restoring them would hand a replaced (often
// leaked) profile its access back.
func cmdUnrevoke(args []string) error {
	fs := flag.NewFlagSet("unrevoke", flag.ExitOnError)
	dir := fs.String("dir", defaultDir, "CA directory")
	name := fs.String("name", "", "client name to un-revoke (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("-name is required")
	}
	if strings.ContainsAny(*name, `/\`) || *name == "." || *name == ".." {
		return fmt.Errorf("-name must be a plain client name (no path separators)")
	}
	serial, err := ca.ClientSerial(*dir, *name)
	if err != nil {
		return err
	}
	removed, err := revoke.New(filepath.Join(*dir, "revoked.json")).RemoveSerial(serial)
	if err != nil {
		return err
	}
	if !removed {
		fmt.Printf("%q's current certificate (serial %s) was not revoked.\n", *name, serial.Text(16))
	} else {
		fmt.Printf("Un-revoked %q (serial %s).\n", *name, serial.Text(16))
	}
	return nil
}

// cmdExportProfile bundles an already-issued client's credentials and the
// server address into a single .vpnio file for easy distribution. It reads the
// public CA cert and the client cert/key from disk — it does NOT touch the CA
// private key, so it can run anywhere the issued client files are present.
func cmdExportProfile(args []string) error {
	fs := flag.NewFlagSet("export-profile", flag.ExitOnError)
	dir := fs.String("dir", defaultDir, "CA directory")
	name := fs.String("name", "", "client name, already issued via issue-client (required)")
	server := fs.String("server", "", "server address clients connect to, host:port (required)")
	serverName := fs.String("server-name", "", "SNI / certificate verification host (optional; defaults to the server host)")
	out := fs.String("out", "", "output file (default: <name>.vpnio)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return fmt.Errorf("-name is required")
	}
	// -name is used to build a file path under the CA dir; reject anything
	// that could climb out of clients/ (e.g. "../server").
	if strings.ContainsAny(*name, `/\`) || *name == "." || *name == ".." {
		return fmt.Errorf("-name must be a plain client name (no path separators)")
	}
	if *server == "" {
		return fmt.Errorf("-server is required")
	}

	caPEM, err := os.ReadFile(filepath.Join(*dir, "ca.crt"))
	if err != nil {
		return fmt.Errorf("read CA certificate: %w", err)
	}
	certPEM, err := os.ReadFile(filepath.Join(*dir, "clients", *name+".crt"))
	if err != nil {
		return fmt.Errorf("read client certificate (issue it first: vpn-ca issue-client -name %s): %w", *name, err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(*dir, "clients", *name+".key"))
	if err != nil {
		return fmt.Errorf("read client key: %w", err)
	}

	data, err := profile.MarshalBundle(caPEM, certPEM, keyPEM, *server, *serverName)
	if err != nil {
		return fmt.Errorf("build profile bundle: %w", err)
	}

	outPath := *out
	if outPath == "" {
		outPath = *name + ".vpnio"
	}
	// The bundle carries the client private key. Remove any existing target and
	// create it fresh with O_EXCL so the file is always 0600: os.WriteFile would
	// leave a pre-existing file's looser mode untouched (perm applies only on
	// creation), and this leaves no window where the key sits world-readable.
	_ = os.Remove(outPath)
	f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", outPath, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(outPath) // don't leave a half-written bundle behind
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	fmt.Printf("Wrote profile %s (client %q, server %s)\n", outPath, *name, *server)
	return nil
}

// cmdBackup writes an encrypted copy of the entire CA directory to one file.
// Losing the root key means re-onboarding every client, so this is the command
// that exists to be run before that happens, not after.
func cmdBackup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	dir := fs.String("dir", defaultDir, "CA directory")
	out := fs.String("out", "", `output file (default: ca-backup-<date>.vpnio-ca)`)
	passFile := fs.String("passphrase-file", "", `file holding the backup passphrase ("-" for stdin; default $VPNIO_CA_PASSPHRASE)`)
	if err := fs.Parse(args); err != nil {
		return err
	}
	pass, err := readPassphrase(*passFile)
	if err != nil {
		return err
	}
	data, err := ca.Backup(*dir, pass)
	if err != nil {
		return err
	}
	outPath := *out
	if outPath == "" {
		outPath = "ca-backup-" + time.Now().Format("2006-01-02") + ".vpnio-ca"
	}
	// O_EXCL, and no silent replace: a backup file is the thing you reach for on
	// the worst day of the project, and overwriting yesterday's copy with a
	// broken one should take a deliberate second command.
	f, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create %s: %w", outPath, err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(outPath)
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write %s: %w", outPath, err)
	}
	fmt.Printf("Wrote %s (%d bytes).\n", outPath, len(data))
	fmt.Println("Store it somewhere the passphrase is not. Without the passphrase it cannot be opened — by anyone, including you.")
	return nil
}

// cmdRestore rebuilds a CA directory from a backup, then re-loads it so the
// command fails here rather than at the next issuance if anything is off.
func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ExitOnError)
	dir := fs.String("dir", defaultDir, "directory to restore the CA into (must not already hold one)")
	in := fs.String("in", "", "backup file to restore (required)")
	passFile := fs.String("passphrase-file", "", `file holding the backup passphrase ("-" for stdin; default $VPNIO_CA_PASSPHRASE)`)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" {
		return fmt.Errorf("-in is required")
	}
	data, err := os.ReadFile(*in)
	if err != nil {
		return fmt.Errorf("read backup: %w", err)
	}
	// Report what this file is before asking the passphrase to do any work: on a
	// recovery day there is usually more than one backup lying around.
	if createdAt, cn, err := ca.BackupInfo(data); err == nil {
		fmt.Printf("Backup of CA %q, taken %s.\n", cn, createdAt.Format("2006-01-02 15:04 MST"))
	}
	pass, err := readPassphrase(*passFile)
	if err != nil {
		return err
	}
	if err := ca.Restore(data, *dir, pass); err != nil {
		return err
	}
	a, err := ca.Load(*dir)
	if err != nil {
		return fmt.Errorf("restored files do not load as a CA: %w", err)
	}
	clients, err := a.ListClients()
	if err != nil {
		return err
	}
	fmt.Printf("Restored CA into %s\n  CN:      %s\n  valid:   until %s\n  clients: %d\n",
		*dir, a.Cert.Subject.CommonName, a.Cert.NotAfter.Format("2006-01-02"), len(clients))
	fmt.Println("Verify it before trusting it: vpn-ca list, then issue a throwaway client and connect with it.")
	return nil
}

// readPassphrase takes the backup passphrase from a file (or stdin for "-"),
// falling back to $VPNIO_CA_PASSPHRASE.
//
// There is deliberately no interactive prompt: a prompt would have to turn
// terminal echo off to be safe, and getting that wrong on some terminal would
// print a root-CA passphrase into a scrollback buffer. A file (or a password
// manager piped into stdin) is both safer and scriptable.
func readPassphrase(file string) (string, error) {
	var raw []byte
	switch {
	case file == "-":
		var err error
		if raw, err = io.ReadAll(io.LimitReader(os.Stdin, 4096)); err != nil {
			return "", fmt.Errorf("read passphrase from stdin: %w", err)
		}
	case file != "":
		var err error
		if raw, err = os.ReadFile(file); err != nil {
			return "", fmt.Errorf("read passphrase file: %w", err)
		}
	default:
		env, ok := os.LookupEnv("VPNIO_CA_PASSPHRASE")
		if !ok || env == "" {
			return "", fmt.Errorf("no passphrase: pass -passphrase-file FILE (or \"-\" for stdin), or set $VPNIO_CA_PASSPHRASE")
		}
		raw = []byte(env)
	}
	// Trim only the trailing newline a file or `echo` adds — not all whitespace,
	// since a passphrase may legitimately end in a space.
	s := strings.TrimRight(string(raw), "\r\n")
	if s == "" {
		return "", fmt.Errorf("passphrase is empty")
	}
	return s, nil
}

func splitHosts(s string) (dns []string, ips []net.IP) {
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, part)
		}
	}
	return
}
