// vpn-vless manages the VLESS/REALITY service that runs next to the vpn.io
// server on a node.
//
// Typical workflow, on the node, as root:
//
//	vpn-vless init -address vpn.example.com
//	vpn-vless add anna
//	systemctl restart vpn-xray
//
// It manages state, not the process: adding or revoking someone rewrites
// /etc/vpn-xray/config.json, and Xray-core reads that file only at start-up, so
// the service has to be restarted for a change to take effect. Every command
// that changes something says so.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/govpn/internal/vless"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "add":
		err = cmdAdd(os.Args[2:])
	case "remove":
		err = cmdRemove(os.Args[2:])
	case "list":
		err = cmdList(os.Args[2:])
	case "link":
		err = cmdLink(os.Args[2:])
	case "render":
		err = cmdRender(os.Args[2:])
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpn-vless:", err)
		if errors.Is(err, vless.ErrNoNode) {
			fmt.Fprintln(os.Stderr, "run `vpn-vless init -address <this node's public address>` first")
		}
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `vpn-vless — VLESS/REALITY access on this node

Commands:
  init -address ADDR   generate this node's REALITY keys and config
  add NAME             issue access and print the vless:// link
  remove NAME          revoke access
  list                 who has access
  link NAME            print someone's link again
  render               rebuild config.json from the stored state

Common flags:
  -dir DIR             state directory (default `+vless.DefaultDir+`)

Changes take effect when the service restarts: systemctl restart vpn-xray
`)
}

// dirFlag registers -dir on fs. Every command takes it so tests and a
// non-standard install can point at another directory.
func dirFlag(fs *flag.FlagSet) *string {
	return fs.String("dir", vless.DefaultDir, "state directory")
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := dirFlag(fs)
	address := fs.String("address", "", "public address clients dial (host or IP)")
	port := fs.Int("port", vless.DefaultPort, "port to listen on")
	dest := fs.String("dest", vless.DefaultDest, "site to impersonate, host:port")
	sni := fs.String("sni", "", "server name clients announce (default: the dest host)")
	fp := fs.String("fp", vless.DefaultFingerprint, "TLS fingerprint clients imitate")
	label := fs.String("label", "", "name client apps show this node as (default: address:port)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *address == "" {
		return errors.New("init needs -address: the host or IP clients will dial")
	}
	n, err := vless.NewNode(*address, *dest, *sni, *fp, *label, *port)
	if err != nil {
		return err
	}
	s := vless.New(*dir)
	if err := s.SaveNode(n); err != nil {
		return err
	}
	// Render immediately, with no clients: the service can then start and be
	// verified from outside before anyone depends on it.
	if err := s.WriteConfig(n, nil); err != nil {
		return err
	}
	fmt.Printf("node initialised in %s\n", s.Dir)
	fmt.Printf("  listening on   %s\n", n.Endpoint())
	fmt.Printf("  impersonating  %s (sni %s)\n", n.Dest, n.ServerName())
	fmt.Printf("  public key     %s\n", n.PublicKey)
	fmt.Println()
	fmt.Println("The private key stays in this directory and is not part of any backup we ship.")
	fmt.Println("Start the service:  systemctl enable --now vpn-xray")
	return nil
}

func cmdAdd(args []string) error {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	dir := dirFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: vpn-vless add NAME")
	}
	s := vless.New(*dir)
	c, err := s.Add(fs.Arg(0))
	if err != nil {
		return err
	}
	n, err := s.LoadNode()
	if err != nil {
		return err
	}
	link, err := vless.Link(n, c)
	if err != nil {
		return err
	}
	fmt.Println(link)
	fmt.Fprintln(os.Stderr)
	// To stderr, so `vpn-vless add someone > link.txt` still yields just the link.
	fmt.Fprintf(os.Stderr, "issued to %s — this link IS the access, send it privately.\n", c.Name)
	fmt.Fprintln(os.Stderr, "Apply it:  systemctl restart vpn-xray")
	return nil
}

func cmdRemove(args []string) error {
	fs := flag.NewFlagSet("remove", flag.ExitOnError)
	dir := dirFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: vpn-vless remove NAME")
	}
	removed, err := vless.New(*dir).Remove(fs.Arg(0))
	if err != nil {
		return err
	}
	if !removed {
		fmt.Printf("%s has no VLESS access — nothing to remove\n", fs.Arg(0))
		return nil
	}
	fmt.Printf("revoked %s\n", fs.Arg(0))
	fmt.Println("Apply it:  systemctl restart vpn-xray")
	return nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	dir := dirFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	clients, err := vless.New(*dir).Clients()
	if err != nil {
		return err
	}
	if len(clients) == 0 {
		fmt.Println("nobody has VLESS access on this node")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tISSUED\tUUID")
	for _, c := range clients {
		// The UUID is a credential; print it truncated so a screenshot of the
		// list does not hand out access.
		fmt.Fprintf(w, "%s\t%s\t%s…\n", c.Name, c.Created, c.UUID[:8])
	}
	return w.Flush()
}

func cmdLink(args []string) error {
	fs := flag.NewFlagSet("link", flag.ExitOnError)
	dir := dirFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: vpn-vless link NAME")
	}
	s := vless.New(*dir)
	c, ok, err := s.Find(fs.Arg(0))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%s has no VLESS access", fs.Arg(0))
	}
	n, err := s.LoadNode()
	if err != nil {
		return err
	}
	link, err := vless.Link(n, c)
	if err != nil {
		return err
	}
	fmt.Println(link)
	return nil
}

func cmdRender(args []string) error {
	fs := flag.NewFlagSet("render", flag.ExitOnError)
	dir := dirFlag(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	s := vless.New(*dir)
	if err := s.Render(); err != nil {
		return err
	}
	fmt.Printf("rebuilt %s\n", s.ConfigPath())
	fmt.Println("Apply it:  systemctl restart vpn-xray")
	return nil
}
