package server

import (
	"errors"
	"io"
)

// runTUNReader is the single goroutine that drains the TUN device and
// fans each packet out to the session for its destination IP.
//
// It owns a single read buffer (one packet at a time) and copies the
// payload before handing it off to the session — the session's writer
// goroutine may not have drained the previous packet yet, so we must not
// alias the read buffer.
func (s *Server) runTUNReader() {
	defer s.wg.Done()

	buf := make([]byte, s.cfg.MTU+64) // +64 for any overhead/safety
	for {
		select {
		case <-s.closeCh:
			return
		default:
		}

		n, err := s.tun.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || isClosedErr(err) {
				return
			}
			s.log.Warn("tun read", "err", err)
			return
		}
		if n == 0 {
			continue
		}
		pkt := buf[:n]
		_, dst, perr := parseIPv4SrcDst(pkt)
		if perr != nil {
			// Drop non-IPv4 (or short) packets silently — IPv6 in particular
			// arrives unsolicited on some platforms.
			continue
		}
		sess := s.registry.ByIPv4(dst)
		if sess == nil {
			// Not destined for any connected client (e.g. server-stack-bound).
			continue
		}
		cp := make([]byte, n)
		copy(cp, pkt)
		if !sess.enqueue(cp) {
			s.log.Debug("dropped outbound packet, queue full",
				"client", sess.CN, "dst", dst)
		}
	}
}
