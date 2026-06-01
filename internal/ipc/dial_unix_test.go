//go:build linux || darwin

package ipc

import "testing"

func TestSocketOwnerAllowed(t *testing.T) {
	const self = 1000
	tests := []struct {
		name  string
		owner uint32
		want  bool
	}{
		{"root-owned", 0, true},
		{"self-owned", self, true},
		{"other user", 1001, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := socketOwnerAllowed(tt.owner, self); got != tt.want {
				t.Errorf("socketOwnerAllowed(%d, %d) = %v, want %v", tt.owner, self, got, tt.want)
			}
		})
	}
}
