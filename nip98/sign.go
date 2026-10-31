package nip98

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// KindHTTPAuth is the NIP-98 HTTP Auth event kind.
const KindHTTPAuth = 27235

// EventSigner signs an event, setting its PubKey, ID and Sig: a key in this
// process (nip46.LocalKey) or a remote signer (nipLS.Client, a NIP-46
// client) alike.
type EventSigner interface {
	Sign(ctx context.Context, ev *nip01.Event) error
}

// ErrNoSigner is a nil EventSigner passed to Sign.
var ErrNoSigner = errors.New("nip98: no signer")

// Sign has signer sign a NIP-98 event for a request to url with method and
// returns the Authorization header value ("Nostr <base64 event>").
//
// A non-nil payload adds a payload tag with its SHA-256, which Verify checks
// against Options.Body; pass []byte{} for a request whose empty body should
// be bound too (a server with RequirePayload asks for that), nil for none.
// Every event also carries a random ["salt", <hex>] tag, so two requests
// signed in the same second get two ids and a server's replay cache
// (Options.Seen) refuses only a real replay. It is not named "nonce": NIP-13
// reads a nonce tag as proof of work, and a remote signer's client that
// verifies the event it gets back (nipLS.Client) would refuse it.
func Sign(ctx context.Context, signer EventSigner, url, method string, payload []byte) (string, error) {
	if signer == nil {
		return "", ErrNoSigner
	}
	ev, err := newEvent(url, method, payload)
	if err != nil {
		return "", err
	}
	if err := signer.Sign(ctx, ev); err != nil {
		return "", fmt.Errorf("nip98: sign: %w", err)
	}
	return encode(ev)
}

// NewAuthHeader is Sign with a private key given as hex.
func NewAuthHeader(privKeyHex, url, method string, body []byte) (string, error) {
	return Sign(context.Background(), keySigner(privKeyHex), url, method, body)
}

type keySigner string

func (k keySigner) Sign(_ context.Context, ev *nip01.Event) error { return ev.Sign(string(k)) }

func newEvent(url, method string, payload []byte) (*nip01.Event, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("nip98: salt: %w", err)
	}
	tags := [][]string{
		{"u", url},
		{"method", method},
	}
	if payload != nil {
		sum := sha256.Sum256(payload)
		tags = append(tags, []string{"payload", hex.EncodeToString(sum[:])})
	}
	tags = append(tags, []string{"salt", hex.EncodeToString(salt)})
	return &nip01.Event{
		Kind:      KindHTTPAuth,
		CreatedAt: uint64(time.Now().Unix()),
		Tags:      tags,
	}, nil
}

func encode(ev *nip01.Event) (string, error) {
	evJSON, err := json.Marshal(ev)
	if err != nil {
		return "", fmt.Errorf("nip98: marshal: %w", err)
	}
	return "Nostr " + base64.StdEncoding.EncodeToString(evJSON), nil
}
