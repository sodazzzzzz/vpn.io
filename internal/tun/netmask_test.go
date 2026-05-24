package tun

import "testing"

func TestNetmaskToPrefixLen(t *testing.T) {
	cases := []struct {
		mask string
		want int
		ok   bool
	}{
		{"255.255.255.0", 24, true},
		{"255.255.0.0", 16, true},
		{"255.0.0.0", 8, true},
		{"255.255.255.255", 32, true},
		{"0.0.0.0", 0, true},
		{"255.255.255.128", 25, true},

		{"255.0.255.0", 0, false}, // non-contiguous
		{"garbage", 0, false},
		{"::1", 0, false}, // IPv6
		{"256.0.0.0", 0, false},
	}
	for _, c := range cases {
		got, err := netmaskToPrefixLen(c.mask)
		if c.ok && err != nil {
			t.Errorf("%s: unexpected error %v", c.mask, err)
			continue
		}
		if !c.ok && err == nil {
			t.Errorf("%s: expected error, got prefix %d", c.mask, got)
			continue
		}
		if c.ok && got != c.want {
			t.Errorf("%s: got %d, want %d", c.mask, got, c.want)
		}
	}
}
