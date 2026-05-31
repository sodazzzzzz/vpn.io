package server

import (
	"net"
	"time"
)

// Connection-lifecycle audit logging.
//
// connect/disconnect/kick are emitted through these helpers so they share one
// field schema: an "event" tag (for filtering), the client CN, its real source
// address, and the assigned tunnel IP — plus session duration on disconnect.
// Everything goes through the server's slog logger; for a self-hosted VPN that
// is enough, no external audit pipeline.

const auditEventKey = "event"

func addrStr(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}

// auditConnect records an admitted client (after AssignIP was sent).
func (s *Server) auditConnect(sess *Session) {
	s.log.Info("client connected",
		auditEventKey, "connect",
		"cn", sess.CN,
		"remote", addrStr(sess.Remote),
		"tun_ip", sess.IP.String(),
	)
}

// auditDisconnect records a client leaving, with how long it stayed connected.
func (s *Server) auditDisconnect(sess *Session) {
	s.log.Info("client disconnected",
		auditEventKey, "disconnect",
		"cn", sess.CN,
		"remote", addrStr(sess.Remote),
		"tun_ip", sess.IP.String(),
		"duration", time.Since(sess.Start).Round(time.Millisecond).String(),
	)
}

// auditKick records a prior session being evicted because the same CN
// reconnected from byRemote.
func (s *Server) auditKick(prev *Session, byRemote net.Addr) {
	s.log.Info("kicking previous session",
		auditEventKey, "kick",
		"cn", prev.CN,
		"remote", addrStr(prev.Remote),
		"tun_ip", prev.IP.String(),
		"by_remote", addrStr(byRemote),
	)
}
