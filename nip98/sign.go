package nip98

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// KindHTTPAuth is the NIP-98 HTTP Auth event kind.
const KindHTTPAuth = 27235

// NewAuthHeader signs a NIP-98 event for a request to url with method and
// returns the Authorization header value ("Nostr <base64 event>"). A non-nil
// body adds a payload tag with its SHA-256, which Verify checks when the
// server passes the body in Options.Body; pass nil for a request without one.
func NewAuthHeader(privKeyHex, url, method string, body []byte) (string, error) {
	tags := [][]string{
		{"u", url},
		{"method", method},
	}
	if body != nil {
		sum := sha256.Sum256(body)
		tags = append(tags, []string{"payload", hex.EncodeToString(sum[:])})
	}

	ev := &nip01.Event{
		Kind:      KindHTTPAuth,
		CreatedAt: uint64(time.Now().Unix()),
		Tags:      tags,
	}
	if err := ev.Sign(privKeyHex); err != nil {
		return "", fmt.Errorf("nip98: sign: %w", err)
	}

	evJSON, err := json.Marshal(ev)
	if err != nil {
		return "", fmt.Errorf("nip98: marshal: %w", err)
	}
	return "Nostr " + base64.StdEncoding.EncodeToString(evJSON), nil
}
