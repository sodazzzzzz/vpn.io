//go:build windows

package ipc

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
)

// pipeName gives each test its own pipe so a leftover from a previous run (or a
// parallel one) can't be mistaken for the pipe under test.
func pipeName(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf(`\\.\pipe\vpn-io-test-%s-%d`, strings.ReplaceAll(t.Name(), "/", "-"), os.Getpid())
}

// A pipe created by an ordinary user must be rejected. This is the squat: an
// unprivileged process creates the helper's pipe name first, the GUI dials it,
// and a ConnectRequest hands over CACertPEM, CertPEM and KeyPEM — the user's
// private key. The test runs unelevated, so the pipe it creates is owned by the
// test user rather than LocalSystem, which is exactly the attacker's position.
func TestVerifyPipeServer_RejectsUnprivilegedOwner(t *testing.T) {
	name := pipeName(t)
	ln, err := winio.ListenPipe(name, &winio.PipeConfig{})
	if err != nil {
		t.Fatalf("ListenPipe: %v", err)
	}
	defer ln.Close()

	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		c, err := ln.Accept()
		if err == nil {
			<-accepted // hold the connection open until the test is done
			_ = c.Close()
		}
	}()

	timeout := 5 * time.Second
	conn, err := winio.DialPipe(name, &timeout)
	if err != nil {
		t.Fatalf("DialPipe: %v", err)
	}
	defer conn.Close()

	err = verifyPipeServer(conn)
	if err == nil {
		t.Fatal("verifyPipeServer accepted a pipe owned by an unprivileged user")
	}
	if !strings.Contains(err.Error(), "owned by") {
		t.Errorf("error = %v, want it to name the offending owner", err)
	}
}

// The check must fail closed: a connection whose handle can't be inspected is
// refused rather than trusted, since sending credentials is the alternative.
func TestVerifyPipeServer_FailsClosedOnUninspectableConn(t *testing.T) {
	if err := verifyPipeServer(nopConn{}); err == nil {
		t.Fatal("verifyPipeServer accepted a connection it could not inspect")
	}
}

// nopConn is a net.Conn with no Fd method, standing in for any connection type
// whose underlying handle we cannot reach.
type nopConn struct{ net.Conn }

// Listen must not join an existing pipe as an extra server instance: that is
// what would let a squatter share the helper's name. go-winio creates the first
// handle with FILE_CREATE, so the second Listen has to fail.
func TestListenPipe_RefusesExistingName(t *testing.T) {
	name := pipeName(t)
	first, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: pipeSDDL})
	if err != nil {
		t.Fatalf("first ListenPipe: %v", err)
	}
	defer first.Close()

	second, err := winio.ListenPipe(name, &winio.PipeConfig{SecurityDescriptor: pipeSDDL})
	if err == nil {
		_ = second.Close()
		t.Fatal("second ListenPipe on the same name succeeded, want a collision error")
	}
}
