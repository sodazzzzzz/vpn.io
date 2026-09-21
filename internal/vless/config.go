package vless

import (
	"encoding/json"
	"fmt"
)

// Config renders the Xray-core configuration for a node and its clients.
//
// The shape is deliberately minimal: one VLESS+REALITY inbound and one direct
// outbound. Everything Xray can also do — routing rules, DNS, statistics, an
// API socket — is another listener or another decision surface on a machine
// that already runs a VPN, so it stays out until something needs it.
//
// Two choices are worth stating, because both are about what this node knows:
//
//   - Access logging is off and sniffing is disabled. Sniffing exists to read
//     the destination hostname out of the proxied stream for routing; we do no
//     routing, so switching it on would only mean the node learns (and could
//     log) every site its users visit. A node that never had the data cannot
//     leak it.
//   - The log level is "warning": enough to see the service fail, not enough to
//     narrate connections.
func Config(n Node, clients []Client) ([]byte, error) {
	if err := n.Validate(); err != nil {
		return nil, err
	}
	type xrayClient struct {
		ID    string `json:"id"`
		Flow  string `json:"flow"`
		Email string `json:"email"`
	}
	xc := make([]xrayClient, 0, len(clients))
	shortIDs := make([]string, 0, len(clients))
	for _, c := range clients {
		if err := c.Validate(); err != nil {
			return nil, err
		}
		xc = append(xc, xrayClient{
			ID:   c.UUID,
			Flow: Flow,
			// Xray calls this field "email"; it is just a label, and it is what
			// shows up in the service's own logs. The client's name is the
			// least surprising thing to put there.
			Email: c.Name,
		})
		shortIDs = append(shortIDs, c.ShortID)
	}

	cfg := map[string]any{
		"log": map[string]any{
			"access":   "none",
			"loglevel": "warning",
		},
		"inbounds": []any{map[string]any{
			"tag":      "vless-reality",
			"listen":   n.ListenAddr(),
			"port":     n.Port,
			"protocol": "vless",
			"settings": map[string]any{
				"clients": xc,
				// REALITY carries the encryption; VLESS itself adds none.
				"decryption": "none",
			},
			"streamSettings": map[string]any{
				"network":  "tcp",
				"security": "reality",
				"realitySettings": map[string]any{
					// show=false keeps handshake debugging out of the log: it is
					// verbose, and it prints what clients connected with.
					"show": false,
					// dest is where this node forwards a handshake it cannot
					// authenticate — anyone scanning the port gets the real site
					// back, which is the entire point of REALITY.
					"dest":        n.Dest,
					"xver":        0,
					"serverNames": n.ServerNames,
					"privateKey":  n.PrivateKey,
					"shortIds":    shortIDs,
				},
			},
			"sniffing": map[string]any{"enabled": false},
		}},
		"outbounds": []any{map[string]any{
			"tag":      "direct",
			"protocol": "freedom",
		}},
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("vless: encode config: %w", err)
	}
	return append(data, '\n'), nil
}
