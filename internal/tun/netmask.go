package tun

import (
	"fmt"
	"math/bits"
	"net"
)

// netmaskToPrefixLen converts a dotted-quad IPv4 netmask ("255.255.255.0")
// into a prefix length (24). It rejects non-contiguous masks like
// "255.0.255.0", which are syntactically valid IPs but illegal as netmasks.
func netmaskToPrefixLen(mask string) (int, error) {
	ip := net.ParseIP(mask)
	if ip == nil {
		return 0, fmt.Errorf("tun: invalid netmask %q", mask)
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0, fmt.Errorf("tun: netmask %q is not IPv4", mask)
	}
	m := net.IPv4Mask(v4[0], v4[1], v4[2], v4[3])
	ones, size := m.Size()
	if size == 0 {
		// net.IPMask.Size returns (0, 0) for non-canonical (non-contiguous) masks.
		return 0, fmt.Errorf("tun: netmask %q is not canonical (non-contiguous bits)", mask)
	}
	// Defense-in-depth: confirm the mask is a contiguous run of 1-bits.
	// net already checked, but make the invariant explicit for readers.
	asUint := uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
	if bits.LeadingZeros32(^asUint)+bits.TrailingZeros32(asUint) != 32 {
		return 0, fmt.Errorf("tun: netmask %q is not contiguous", mask)
	}
	return ones, nil
}
