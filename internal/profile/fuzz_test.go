package profile

import (
	"strings"
	"testing"
)

// FuzzParseBundle throws malformed and hostile .vpnio files at the importer.
//
// The bundle is the one file a user is told to open from a chat message, so it
// is the most likely thing in this project to arrive from somewhere untrusted.
// It must fail with an error on anything it does not understand — never panic,
// and never return a Profile that later code would treat as usable.
func FuzzParseBundle(f *testing.F) {
	f.Add([]byte(`{"version":1,"server":"vpn.example.com:8443","ca":"","cert":"","key":""}`))
	f.Add([]byte(`{"version":999,"server":"h:1","ca":"x","cert":"y","key":"z"}`))
	f.Add([]byte(`{"version":1,"server":"","ca":"-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----","cert":"","key":""}`))
	f.Add([]byte(`{"version":1,"server":"h:1","ca":"-----BEGIN CERTIFICATE-----","cert":"-----BEGIN CERTIFICATE-----","key":"-----BEGIN PRIVATE KEY-----"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(`[1,2,3]`))
	f.Add([]byte(strings.Repeat("{", 200))) // deeply nested JSON

	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ParseBundle(data)
		if err != nil {
			if p != nil {
				t.Fatal("ParseBundle returned both a profile and an error")
			}
			return
		}
		if p == nil {
			t.Fatal("ParseBundle returned no profile and no error")
		}
		// Anything that parsed successfully must be complete: the client dials
		// Server and presents these credentials without re-checking them.
		if p.Server == "" {
			t.Fatal("accepted a bundle with no server address")
		}
		if len(p.CACertPEM) == 0 || len(p.CertPEM) == 0 || len(p.KeyPEM) == 0 {
			t.Fatal("accepted a bundle with missing credentials")
		}
		// String() must not leak the private key — this type is passed to
		// loggers and error messages.
		if s := p.String(); strings.Contains(s, "PRIVATE KEY") {
			t.Fatalf("Profile.String leaks key material: %s", s)
		}
	})
}
