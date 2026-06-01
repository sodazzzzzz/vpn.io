package ipc

import (
	"fmt"
	"time"
)

// dialTimeout bounds how long Do waits to connect to the control socket.
const dialTimeout = 5 * time.Second

// Do connects to the daemon's control socket at path, sends one request, and
// returns the daemon's response. One request per connection, matching the
// server side. The transport is the platform's local IPC (a unix socket on
// linux/darwin); on platforms without one implemented, dialControl returns
// ErrTransportUnsupported.
func Do(path string, req Request) (Response, error) {
	conn, err := dialControl(path)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = conn.Close() }()

	// One deadline for the whole round-trip — send and read back. If this
	// fails the read below could block forever on a stuck daemon, so surface
	// it rather than proceeding without a timeout.
	if err := conn.SetDeadline(time.Now().Add(requestTimeout)); err != nil {
		return Response{}, fmt.Errorf("ipc: set deadline: %w", err)
	}

	if err := WriteRequest(conn, req); err != nil {
		return Response{}, fmt.Errorf("ipc: send request: %w", err)
	}
	resp, err := ReadResponse(conn)
	if err != nil {
		return Response{}, fmt.Errorf("ipc: read response: %w", err)
	}
	return resp, nil
}
