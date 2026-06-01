package ipc

// Policy decides which connecting peers the daemon accepts, identified by
// the OS-verified user and group IDs of the process on the other end of
// the socket. root (uid 0) is always allowed — it is already as privileged
// as the daemon. Any other peer must match AllowUID or AllowGID.
//
// An empty policy therefore admits only root, which is the safe default: a
// front-end running as a normal user is granted access explicitly by the
// operator (the GUI-integration step wires in the desktop user's uid).
type Policy struct {
	AllowUID []uint32

	// AllowGID matches only the peer's effective/primary group, not its
	// supplementary groups: Linux SO_PEERCRED reports just the effective gid,
	// and the macOS path checks the primary group (Groups[0]) only. A user
	// granted access via a supplementary group (e.g. `usermod -aG vpn`) is
	// therefore NOT matched — prefer AllowUID, or make it the user's primary
	// group.
	AllowGID []uint32
}

// allow reports whether a peer with the given uid/gid may connect.
func (p Policy) allow(uid, gid uint32) bool {
	if uid == 0 {
		return true
	}
	for _, u := range p.AllowUID {
		if u == uid {
			return true
		}
	}
	for _, g := range p.AllowGID {
		if g == gid {
			return true
		}
	}
	return false
}
