// Command vpn-ctl is the command-line front-end for the vpn-helper daemon.
// It loads and validates client credentials locally, then drives the daemon
// over its control socket: connect, disconnect, status.
//
// It needs no special privileges itself — the daemon holds them. The socket
// admits only root and the uids/gids the daemon is configured to allow, so
// vpn-ctl must run as a permitted user (see packaging/README.md).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/govpn/internal/ipc"
	"github.com/govpn/internal/profile"
)

// defaultSocket matches cmd/vpn-helper's default. The systemd unit uses
// /run/vpn-io/helper.sock — pass -socket to match it.
const defaultSocket = "/var/run/vpn-io-helper.sock"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "connect":
		runConnect(os.Args[2:])
	case "disconnect":
		runDisconnect(os.Args[2:])
	case "status":
		runStatus(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "vpn-ctl: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `vpn-ctl — control the vpn-helper daemon

usage:
  vpn-ctl connect    -ca FILE -cert FILE -key FILE -server HOST:PORT [options]
  vpn-ctl status     [-socket PATH]
  vpn-ctl disconnect [-socket PATH]

Run "vpn-ctl <command> -h" for command-specific options.
`)
}

func runConnect(args []string) {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	socket := fs.String("socket", defaultSocket, "daemon control socket path")
	ca := fs.String("ca", "", "CA certificate file (PEM)")
	cert := fs.String("cert", "", "client certificate file (PEM)")
	key := fs.String("key", "", "client private key file (PEM)")
	server := fs.String("server", "", "server address, host:port")
	serverName := fs.String("server-name", "", "TLS SNI / verification host (default = host of -server)")
	mtu := fs.Int("mtu", 0, "TUN MTU (0 = daemon default)")
	tunName := fs.String("tun-name", "", "TUN interface name (empty = driver picks)")
	_ = fs.Parse(args)

	if *ca == "" || *cert == "" || *key == "" || *server == "" {
		fmt.Fprintln(os.Stderr, "vpn-ctl connect: -ca, -cert, -key and -server are required")
		fs.Usage()
		os.Exit(2)
	}

	// Validate credentials locally first: a clear error here beats an opaque
	// failure inside the daemon's TLS handshake later.
	prof, err := profile.Load(profile.Files{
		CACert:     *ca,
		Cert:       *cert,
		Key:        *key,
		Server:     *server,
		ServerName: *serverName,
	})
	if err != nil {
		fatal("invalid credentials: %v", err)
	}

	payload, err := json.Marshal(ipc.ConnectRequest{
		Server:     prof.Server,
		ServerName: prof.ServerName,
		CACertPEM:  prof.CACertPEM,
		CertPEM:    prof.CertPEM,
		KeyPEM:     prof.KeyPEM,
		MTU:        *mtu,
		TunName:    *tunName,
	})
	if err != nil {
		fatal("encode request: %v", err)
	}

	resp := do(*socket, ipc.Request{Command: ipc.CmdConnect, Payload: payload})
	if !resp.OK {
		fatal("connect rejected: %s", resp.Error)
	}
	fmt.Printf("connecting as %s (certificate expires %s)\n",
		prof.CommonName, prof.NotAfter.Format(time.RFC3339))
}

func runDisconnect(args []string) {
	fs := flag.NewFlagSet("disconnect", flag.ExitOnError)
	socket := fs.String("socket", defaultSocket, "daemon control socket path")
	_ = fs.Parse(args)

	resp := do(*socket, ipc.Request{Command: ipc.CmdDisconnect})
	if !resp.OK {
		fatal("disconnect failed: %s", resp.Error)
	}
	fmt.Println("disconnected")
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	socket := fs.String("socket", defaultSocket, "daemon control socket path")
	_ = fs.Parse(args)

	resp := do(*socket, ipc.Request{Command: ipc.CmdStatus})
	if !resp.OK {
		fatal("status failed: %s", resp.Error)
	}
	var st ipc.StatusResponse
	if err := json.Unmarshal(resp.Payload, &st); err != nil {
		fatal("decode status: %v", err)
	}

	fmt.Printf("state:  %s\n", st.State)
	if st.Server != "" {
		fmt.Printf("server: %s\n", st.Server)
	}
	if st.SinceUnix != 0 {
		fmt.Printf("since:  %s\n", time.Unix(st.SinceUnix, 0).Format(time.RFC3339))
	}
	if st.LastError != "" {
		fmt.Printf("error:  %s\n", st.LastError)
	}
}

// do sends one request to the daemon, exiting with a clear message on a
// transport error (the common case being "daemon not running").
func do(socket string, req ipc.Request) ipc.Response {
	resp, err := ipc.Do(socket, req)
	if err != nil {
		fatal("%v", err)
	}
	return resp
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "vpn-ctl: "+format+"\n", args...)
	os.Exit(1)
}
