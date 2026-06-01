package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
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
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.ln.Close()
	}()

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // shutdown closed the listener
			}
			// Unauthorized peers are filtered inside the listener's Accept
			// (it closes them and loops), so anything surfacing here is a
			// real listener failure.
			return fmt.Errorf("ipc: accept: %w", err)
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(requestTimeout))

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
