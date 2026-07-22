package ipc

import (
	"context"
	"encoding/json"
	"net"
	"testing"
)

func TestPolicyAllow(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
		uid    uint32
		gid    uint32
		want   bool
	}{
		{"root always allowed", Policy{}, 0, 0, true},
		{"root allowed despite wrong gid", Policy{}, 0, 999, true},
		{"empty policy rejects non-root", Policy{}, 1000, 1000, false},
		{"uid match", Policy{AllowUID: []uint32{1000}}, 1000, 50, true},
		{"uid no match", Policy{AllowUID: []uint32{1000}}, 1001, 50, false},
		{"gid match", Policy{AllowGID: []uint32{20}}, 1001, 20, true},
		{"neither match", Policy{AllowUID: []uint32{1000}, AllowGID: []uint32{20}}, 1001, 21, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.policy.allow(tt.uid, tt.gid); got != tt.want {
				t.Errorf("allow(%d,%d) = %v, want %v", tt.uid, tt.gid, got, tt.want)
			}
		})
	}
}

func TestRequestResponseRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	want := Request{Command: CmdConnect, Payload: json.RawMessage(`{"server":"x:1"}`)}
	go func() {
		_ = WriteRequest(a, want)
	}()

	got, err := ReadRequest(b)
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if got.Command != want.Command || string(got.Payload) != string(want.Payload) {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}
}

// fakeHandler records calls and returns canned results.
type fakeHandler struct {
	lastConnect ConnectRequest
	connectErr  error
	disconnects int
	status      StatusResponse
}

func (f *fakeHandler) Connect(r ConnectRequest) error { f.lastConnect = r; return f.connectErr }
func (f *fakeHandler) Disconnect() error              { f.disconnects++; return nil }
func (f *fakeHandler) Status() StatusResponse         { return f.status }

func TestDispatchStatus(t *testing.T) {
	h := &fakeHandler{status: StatusResponse{State: "connected", Server: "vpn:8443"}}
	s := NewServer(nil, h, nil)

	resp := s.dispatch(Request{Command: CmdStatus})
	if !resp.OK {
		t.Fatalf("status not ok: %q", resp.Error)
	}
	var got StatusResponse
	if err := json.Unmarshal(resp.Payload, &got); err != nil {
		t.Fatalf("unmarshal status: %v", err)
	}
	if got.State != "connected" || got.Server != "vpn:8443" {
		t.Fatalf("unexpected status payload: %+v", got)
	}
}

func TestDispatchUnknownCommand(t *testing.T) {
	s := NewServer(nil, &fakeHandler{}, nil)
	resp := s.dispatch(Request{Command: "bogus"})
	if resp.OK {
		t.Fatal("expected unknown command to fail")
	}
}

// A front-end newer than the daemon is refused with a clear message; a legacy
// (Version 0) or same-version front-end is accepted (#143).
func TestDispatchRejectsNewerFrontEnd(t *testing.T) {
	s := NewServer(nil, &fakeHandler{status: StatusResponse{State: "disconnected"}}, nil)

	resp := s.dispatch(Request{Command: CmdStatus, Version: IPCVersion + 1})
	if resp.OK || resp.Error == "" {
		t.Fatalf("newer front-end should be rejected, got %+v", resp)
	}

	for _, v := range []int{0, IPCVersion} {
		if resp := s.dispatch(Request{Command: CmdStatus, Version: v}); !resp.OK {
			t.Fatalf("front-end version %d should be accepted, got %q", v, resp.Error)
		}
	}
}

func TestDispatchConnectPropagatesError(t *testing.T) {
	h := &fakeHandler{connectErr: context.DeadlineExceeded}
	s := NewServer(nil, h, nil)
	payload, _ := json.Marshal(ConnectRequest{Server: "x:1"})
	resp := s.dispatch(Request{Command: CmdConnect, Payload: payload})
	if resp.OK || resp.Error == "" {
		t.Fatalf("expected connect error, got %+v", resp)
	}
	if h.lastConnect.Server != "x:1" {
		t.Fatalf("handler did not receive payload: %+v", h.lastConnect)
	}
}
