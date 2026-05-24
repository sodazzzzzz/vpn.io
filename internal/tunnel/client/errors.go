package client

import "errors"

// Sentinel errors for non-retryable failures. The reconnect loop checks
// these via errors.Is and aborts instead of backing off.

// ErrFatalAuth means the TLS handshake or first-frame read surfaced a
// credential problem (unknown CA, bad client cert, missing client cert).
// Retrying with the same files will hit the same wall.
var ErrFatalAuth = errors.New("client: tls authentication failed")

// ErrFatalServer means the server sent an explicit Error control message
// (e.g. "no_ip") instead of an AssignIP. The server has told us this
// connection will never succeed; retry would loop forever.
var ErrFatalServer = errors.New("client: server reported error")

// ErrFatalConfig means tun.Configure failed (typically: not enough
// privileges, or the OS rejected the address). Retrying without root /
// admin won't help.
var ErrFatalConfig = errors.New("client: TUN configuration failed")
