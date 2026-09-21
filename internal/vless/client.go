package vless

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// NewClient mints access for name: a fresh UUID and a fresh shortId.
//
// Nothing here is derived from the name. A UUID that could be guessed from who
// someone is would be a credential anyone could forge, so both values come from
// the system CSPRNG and the name is only a label.
func NewClient(name string) (Client, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Client{}, fmt.Errorf("vless: client name is required")
	}
	id, err := newUUID()
	if err != nil {
		return Client{}, err
	}
	sid, err := newShortID()
	if err != nil {
		return Client{}, err
	}
	c := Client{
		Name:    name,
		UUID:    id,
		ShortID: sid,
		Created: time.Now().UTC().Format(time.RFC3339),
	}
	if err := c.Validate(); err != nil {
		return Client{}, err
	}
	return c, nil
}

// Validate reports whether the client is usable. Like Node.Validate it runs on
// load too, so a hand-edited clients.json fails here instead of producing an
// Xray config that Xray rejects at start-up — which, on a restart triggered by
// adding someone, would take the service down for everyone.
func (c Client) Validate() error {
	if strings.TrimSpace(c.Name) == "" {
		return fmt.Errorf("vless: client has no name")
	}
	if err := validUUID(c.UUID); err != nil {
		return fmt.Errorf("vless: client %q: %w", c.Name, err)
	}
	if err := validShortID(c.ShortID); err != nil {
		return fmt.Errorf("vless: client %q: %w", c.Name, err)
	}
	return nil
}

// newUUID returns a random (version 4) UUID in the canonical 8-4-4-4-12 form
// Xray expects.
func newUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("vless: generate uuid: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	s := hex.EncodeToString(b[:])
	return s[0:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}

// validUUID checks the canonical form: 36 characters, hyphens in the right
// places, hex everywhere else.
func validUUID(s string) error {
	if len(s) != 36 {
		return fmt.Errorf("uuid %q is not 36 characters", s)
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return fmt.Errorf("uuid %q is malformed", s)
			}
		default:
			if !isHex(r) {
				return fmt.Errorf("uuid %q is malformed", s)
			}
		}
	}
	return nil
}

// validShortID checks a REALITY shortId: lowercase hex, an even number of
// characters, at most 8 bytes. An empty shortId is legal in REALITY but not
// here — we always issue one, and an empty value in the list would quietly
// admit clients that send none.
func validShortID(s string) error {
	switch {
	case s == "":
		return fmt.Errorf("shortId is empty")
	case len(s)%2 != 0:
		return fmt.Errorf("shortId %q has an odd number of hex digits", s)
	case len(s) > shortIDBytes*2:
		return fmt.Errorf("shortId %q is longer than %d bytes", s, shortIDBytes)
	}
	for _, r := range s {
		if !isHex(r) || (r >= 'A' && r <= 'F') {
			return fmt.Errorf("shortId %q is not lowercase hex", s)
		}
	}
	return nil
}

func isHex(r rune) bool {
	return (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
}
