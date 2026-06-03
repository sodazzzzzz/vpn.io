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
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/govpn/internal/ca"
	"github.com/govpn/internal/profile"
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
  list         [-dir DIR]                                     list issued clients
  export-profile [-dir DIR] -name NAME -server HOST:PORT [-server-name S] [-out FILE]
                                                              bundle a client into one .vpnio file

Default -dir is ./ca-data.
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
		return nil
	}
	fmt.Println("Clients:")
	for _, c := range clients {
		fmt.Printf("  - %s\n", c)
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
