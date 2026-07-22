//go:build !windows

package ipc

import "net"

// authorizePeer is a no-op off Windows: the unix listener already gates every
// accepted connection by the peer's kernel credentials (see listen_unix.go), so
// by the time a connection reaches the server it is already authorized. This
// keeps server.go's handle path platform-neutral.
func authorizePeer(net.Conn) error { return nil }
