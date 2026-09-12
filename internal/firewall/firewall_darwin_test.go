//go:build darwin

package firewall

import "testing"

// TestParseV6Mode feeds parseV6Mode real `networksetup -getinfo` dumps. The
// unconfigured-service dump is the trap: it carries "IPv6 IP address:" and
// "IPv6 Router:" lines around (or instead of) the bare "IPv6:" one, and
// mistaking either for the mode would hand Enable a value it can't restore.
func TestParseV6Mode(t *testing.T) {
	cases := []struct {
		name string
		out  string
		want string
	}{
		{
			name: "dhcp service with IPv6 automatic",
			out: `DHCP Configuration
IP address: 172.20.10.9
Subnet mask: 255.255.255.240
Router: 172.20.10.1
Client ID:
IPv6: Automatic
IPv6 IP address: none
IPv6 Router: none
Ethernet Address: 3c:22:fb:11:22:33
`,
			want: "Automatic",
		},
		{
			name: "service with IPv6 already off",
			out: `DHCP Configuration
Client ID:
IPv6: Off
Ethernet Address: (null)
`,
			want: "Off",
		},
		{
			name: "link-local",
			out: `Manual Configuration
IP address: 10.0.0.2
IPv6: Link-local
IPv6 IP address: fe80::1
`,
			want: "Link-local",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseV6Mode([]byte(tc.out))
			if err != nil {
				t.Fatalf("parseV6Mode: %v", err)
			}
			if got != tc.want {
				t.Fatalf("mode = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestParseV6ModeErrors covers the dumps we must not read a mode out of: a
// service that reports no IPv6 line at all, and the usage text networksetup
// prints for a verb it doesn't know (which is what a wrong flag looked like).
func TestParseV6ModeErrors(t *testing.T) {
	cases := []struct {
		name string
		out  string
	}{
		{
			name: "no IPv6 line",
			out: `DHCP Configuration
IP address: 10.0.0.5
Ethernet Address: (null)
`,
		},
		{
			name: "usage dump from an unknown verb",
			out: `networksetup -listnetworkserviceorder
networksetup -getinfo <networkservice>
** Error: The command is not recognized.
`,
		},
		{
			name: "empty mode",
			out:  "IPv6:\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseV6Mode([]byte(tc.out)); err == nil {
				t.Fatal("expected an error, got a mode")
			}
		})
	}
}
