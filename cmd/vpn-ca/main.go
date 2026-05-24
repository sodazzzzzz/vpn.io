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
	"strings"

	"github.com/govpn/internal/ca"
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
