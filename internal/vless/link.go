package vless

import (
	"net/url"
	"strconv"
)

// Link renders the vless:// URI a client app imports.
//
// The format is the de-facto one every VLESS client reads (Happ included): the
// UUID as userinfo, the node as host:port, transport and REALITY parameters in
// the query, and a human label in the fragment. There is no standards document
// behind it — compatibility comes from matching what clients parse, which is
// why the parameter set here is covered by tests rather than trusted to memory.
//
// The link is a credential. It carries the UUID, so handing it to someone is
// handing them access: it travels the same way a .vpnio bundle does — private
// chat only, never a group.
func Link(n Node, c Client) (string, error) {
	if err := n.Validate(); err != nil {
		return "", err
	}
	if err := c.Validate(); err != nil {
		return "", err
	}
	q := url.Values{
		// Transport: plain TCP carrying REALITY.
		"type":     {"tcp"},
		"security": {"reality"},
		// VLESS adds no encryption of its own; REALITY provides it.
		"encryption": {"none"},
		"flow":       {Flow},
		// pbk is the node's public key, sni the name the client announces, sid
		// the client's shortId — the three values REALITY cannot work without.
		"pbk": {n.PublicKey},
		"sni": {n.ServerName()},
		"sid": {c.ShortID},
		// fp tells the client which TLS fingerprint to imitate. It matters on
		// the client side, not here: the node's job is to look like the site it
		// forwards to, the client's job is to look like an ordinary browser.
		"fp": {n.Fingerprint},
	}
	u := url.URL{
		Scheme:   "vless",
		User:     url.User(c.UUID),
		Host:     n.Endpoint(),
		RawQuery: q.Encode(),
		Fragment: n.LinkLabel(),
	}
	return u.String(), nil
}

// LinkLabel is what a client app shows this node as in its server list.
func (n Node) LinkLabel() string {
	if n.Label != "" {
		return n.Label
	}
	return n.Address + ":" + strconv.Itoa(n.Port)
}
