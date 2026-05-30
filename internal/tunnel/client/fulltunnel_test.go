package client

import "testing"

func TestIsFullTunnel(t *testing.T) {
	tests := []struct {
		name   string
		routes []string
		want   bool
	}{
		{"nil", nil, false},
		{"empty", []string{}, false},
		{"split-only", []string{"10.0.0.0/8", "192.168.0.0/16"}, false},
		{"ipv4 default", []string{"0.0.0.0/0"}, true},
		{"default among specifics", []string{"10.0.0.0/8", "0.0.0.0/0"}, true},
		{"ipv6 default", []string{"::/0"}, true},
		{"bad cidr ignored", []string{"not-a-cidr"}, false},
		{"bad cidr plus default", []string{"nope", "0.0.0.0/0"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isFullTunnel(tt.routes); got != tt.want {
				t.Fatalf("isFullTunnel(%v) = %v, want %v", tt.routes, got, tt.want)
			}
		})
	}
}
