package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// requestTimeout caps how long a single accepted connection may take to
// deliver its one request. It stops an idle or stuck peer from holding a
// connection (and, via the handler, the tunnel lock) open indefinitely.
const requestTimeout = 10 * time.Second

// Handler executes the commands carried over IPC. Implementations must be
// safe for concurrent use: the server may dispatch from multiple accepted
// connections. The daemon's tunnel controller satisfies this interface.
type Handler interface {
	Connect(ConnectRequest) error
	Disconnect() error
	Status() StatusResponse
}

// Server reads one request per accepted connection, dispatches it to the
// Handler, and writes back one response. The listener is expected to have
// already authenticated the peer (see Listen).
type Server struct {
	ln  net.Listener
	h   Handler
	log *slog.Logger
}

// NewServer wraps ln and h. The caller owns ln and should close it (or
// cancel Serve's context) to stop the server.
func NewServer(ln net.Listener, h Handler, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{ln: ln, h: h, log: log}
}

// Serve accepts connections until ctx is cancelled or the listener fails.
// Cancelling ctx closes the listener, which unblocks Accept; the resulting
// error is reported as a clean shutdown (nil).
//
// Serve does not return until every in-flight handler has finished. That
// ordering matters: the caller tears the tunnel down (ctrl.Disconnect) after
// Serve returns, so a handler that is mid-Connect must not still be running —
// otherwise it could start a session right after Disconnect and leave routes,
// DNS and firewall rules applied as the process exits.
func (s *Server) Serve(ctx context.Context) error {
	// Stop the listener on ctx cancel; stopWatch ends the watcher when Serve
	// returns for any other reason, so it never leaks.
	stopWatch := make(chan struct{})
	defer close(stopWatch)
	go func() {
		select {
		case <-ctx.Done():
			_ = s.ln.Close()
		case <-stopWatch:
		}
	}()

	var wg sync.WaitGroup
	var acceptFails int
	var retryDelay time.Duration
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				wg.Wait()
				return nil // shutdown closed the listener
			}
			// A transient listener error (fd exhaustion — EMFILE, a connection
			// aborted before Accept, an interrupted syscall) is recoverable. The
			// control plane must NOT tear the live tunnel down over a momentary
			// condition, so back off and keep accepting. Give up only when
			// failures persist with no success in between — a genuinely broken
			// listener — rather than spinning forever. (net.Error.Temporary is
			// deprecated and the relevant errnos aren't portable, so we classify
			// by persistence instead of type.)
			acceptFails++
			if acceptFails >= maxAcceptFailures {
				wg.Wait()
				return fmt.Errorf("ipc: accept failed %d times in a row: %w", acceptFails, err)
			}
			retryDelay = nextAcceptDelay(retryDelay)
			s.log.Warn("ipc: transient accept error; retrying",
				"err", err, "in", retryDelay, "streak", acceptFails)
			select {
			case <-time.After(retryDelay):
			case <-ctx.Done():
				wg.Wait()
				return nil
			}
			continue
		}
		acceptFails, retryDelay = 0, 0
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handle(conn)
		}()
	}
}

// maxAcceptFailures bounds consecutive Accept failures before Serve gives up. A
// transient blip recovers well within this; a genuinely dead listener shouldn't
// spin forever.
const maxAcceptFailures = 10

// nextAcceptDelay is the exponential backoff (5ms doubling, capped at 1s)
// applied between failed Accepts.
func nextAcceptDelay(d time.Duration) time.Duration {
	if d == 0 {
		return 5 * time.Millisecond
	}
	if d *= 2; d > time.Second {
		return time.Second
	}
	return d
}

func (s *Server) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(requestTimeout))

	// Gate the connection by the caller's identity before reading its command.
	// On unix the listener already did this via peer credentials, so this is a
	// no-op there; on Windows it's the real check that the caller is the console
	// user, since the pipe SDDL alone can't express that (#178).
	if err := authorizePeer(conn); err != nil {
		s.log.Warn("ipc: rejected unauthorized control client", "err", err)
		_ = WriteResponse(conn, errResponse(errors.New("not authorized to control the tunnel")))
		return
	}

	req, err := ReadRequest(conn)
	if err != nil {
		s.log.Debug("ipc: read request", "err", err)
		return
	}

	resp := s.dispatch(req)
	if err := WriteResponse(conn, resp); err != nil {
		s.log.Debug("ipc: write response", "err", err)
	}
}

func (s *Server) dispatch(req Request) Response {
	switch req.Command {
	case CmdConnect:
		var cr ConnectRequest
		if err := json.Unmarshal(req.Payload, &cr); err != nil {
			return errResponse(fmt.Errorf("decode connect payload: %w", err))
		}
		if err := s.h.Connect(cr); err != nil {
			return errResponse(err)
		}
		return Response{OK: true}

	case CmdDisconnect:
		if err := s.h.Disconnect(); err != nil {
			return errResponse(err)
		}
		return Response{OK: true}

	case CmdStatus:
		payload, err := json.Marshal(s.h.Status())
		if err != nil {
			return errResponse(fmt.Errorf("encode status: %w", err))
		}
		return Response{OK: true, Payload: payload}

	default:
		return errResponse(fmt.Errorf("unknown command %q", req.Command))
	}
}

func errResponse(err error) Response {
	if err == nil {
		err = errors.New("unknown error")
	}
	return Response{OK: false, Error: err.Error()}
}
