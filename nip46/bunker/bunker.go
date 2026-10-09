// Package bunker runs NIP-46 remote signing over relays: a Client that
// signs through a remote signer, and a Server that is one.
//
// Client side, pairing from a bunker:// URI the signer showed:
//
//	c, err := bunker.Dial(ctx, "bunker://<signer-pubkey>?relay=wss://...&secret=...", bunker.ClientOptions{})
//	if err != nil { ... }
//	defer c.Close()
//	err = c.Sign(ctx, ev)
//	saved := c.Session() // keep it to reconnect later without a new secret
//
// or showing a nostrconnect:// URI for the signer to scan:
//
//	p, err := bunker.NewPairing([]string{"wss://relay.example"}, bunker.ClientOptions{Metadata: &nip46.Metadata{Name: "my app"}})
//	show(p.URI())
//	c, err := p.Wait(ctx)
//
// Server side:
//
//	key, _ := nip46.NewLocalKey(nsec)
//	srv, _ := bunker.NewServer(bunker.ServerConfig{Key: key, Relays: relays, Policy: myPolicy})
//	go srv.Run(ctx)
//	uri, _ := srv.NewBunkerURI(5 * time.Minute)   // or srv.AcceptNostrconnect(ctx, uri)
//
// *Client implements nip46.Signer and nip46.Key, like *nip46.LocalKey and
// nipLS.Client, so code that signs doesn't care where the key lives.
package bunker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip19"
	"github.com/ohstr/nmilat/nip46"
)

const (
	// URIScheme is the scheme of a signer-generated connection URI.
	URIScheme = "bunker"

	// secretByteLen matches the pairing-secret entropy other NIP-46
	// signers use.
	secretByteLen = 16
)

// URI is a parsed bunker://<signer-pubkey>?relay=...&secret=... string.
type URI struct {
	// SignerPubKey is the pubkey the signer talks on, lowercase hex. It
	// may differ from the user pubkey the signer signs as.
	SignerPubKey string
	// Relays lists every relay param, in order; at least one.
	Relays []string
	// Secret is the optional single-use pairing secret.
	Secret string
}

// ParseURI parses a bunker:// URI. A relay given without a scheme is read
// as wss://; non-websocket relays are rejected.
func ParseURI(s string) (*URI, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("bunker: invalid URI: %w", err)
	}
	if !strings.EqualFold(u.Scheme, URIScheme) {
		return nil, fmt.Errorf("bunker: want a %s:// URI, got %q", URIScheme, u.Scheme)
	}
	if err := nip19.CheckPublicKey(u.Host); err != nil {
		return nil, fmt.Errorf("bunker: invalid signer pubkey: %w", err)
	}
	q := u.Query()
	var relays []string
	for _, raw := range q["relay"] {
		r, err := normalizeRelay(raw)
		if err != nil {
			continue
		}
		relays = append(relays, r)
	}
	if len(relays) == 0 {
		return nil, errors.New("bunker: URI names no usable relay")
	}
	return &URI{SignerPubKey: strings.ToLower(u.Host), Relays: relays, Secret: q.Get("secret")}, nil
}

// String formats u as a bunker:// URI.
func (u *URI) String() string {
	q := url.Values{}
	for _, r := range u.Relays {
		q.Add("relay", r)
	}
	if u.Secret != "" {
		q.Set("secret", u.Secret)
	}
	return (&url.URL{Scheme: URIScheme, Host: u.SignerPubKey, RawQuery: q.Encode()}).String()
}

// NewSecret returns a fresh random pairing secret, hex-encoded.
func NewSecret() (string, error) {
	b := make([]byte, secretByteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("bunker: generate secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// normalizeRelay reads a relay param, defaulting to wss:// and rejecting
// anything that isn't a websocket URL with a host.
func normalizeRelay(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("empty relay")
	}
	if !strings.Contains(raw, "://") {
		raw = "wss://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	switch strings.ToLower(u.Scheme) {
	case "ws", "wss":
	default:
		return "", fmt.Errorf("unsupported relay scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return "", errors.New("relay has no host")
	}
	return u.String(), nil
}

// Call is one request as a Policy, a custom Handler or the decision hook
// sees it.
type Call struct {
	// ID is the client's request id.
	ID string
	// Method is the NIP-46 method name.
	Method string
	// Params are the decrypted request params.
	Params []string
	// Client is the requesting app's pubkey, lowercase hex.
	Client string
	// Encryption is the scheme the request arrived in, and the response
	// will use.
	Encryption string

	// Event is sign_event's event with PubKey and ID set to exactly what
	// the signature will cover. It is a copy: changing it has no effect.
	Event *nip01.Event

	// Counterpart is the nip04_*/nip44_* peer pubkey, lowercase hex.
	Counterpart string
	// Plaintext is set for nip04_encrypt and nip44_encrypt.
	Plaintext string
	// Ciphertext is set for nip04_decrypt and nip44_decrypt.
	Ciphertext string

	// Secret is the pairing secret a connect presented; the server only
	// lets a connect reach the policy once it matched an armed secret.
	Secret string
	// Perms is the permission list a connect asked for, raw
	// ("sign_event:1,nip44_encrypt"); a request, not a grant.
	Perms string
	// Metadata is the app's self-description from connect. Unauthenticated:
	// a display hint, never an input to an authorization decision.
	Metadata *nip46.Metadata

	// Rule optionally names what decided, for the decision hook. A Policy
	// may set it.
	Rule string
}

// Policy decides every request a paired or pairing app makes. Return nil
// to allow, nip46.Deny(reason) to refuse, or nip46.Invalid(reason) for a
// malformed request; any other error refuses with its message.
//
// Authorize may block, e.g. while a human approves; each request runs on
// its own goroutine. A connect reaches it only after presenting an armed
// secret (NewBunkerURI); a nostrconnect:// pairing (AcceptNostrconnect) is
// the operator's own decision and does not.
type Policy interface {
	Authorize(ctx context.Context, call *Call) error
}

// PolicyFunc adapts a function to Policy.
type PolicyFunc func(ctx context.Context, call *Call) error

// Authorize calls f.
func (f PolicyFunc) Authorize(ctx context.Context, call *Call) error { return f(ctx, call) }

// Handler answers a custom method. Custom methods are policy-gated like
// the built-in ones.
type Handler func(ctx context.Context, call *Call) (string, error)

// Decision reports one request's outcome to ServerConfig.OnDecision.
type Decision struct {
	Time time.Time
	Call *Call
	// Err is nil when the request was allowed and carried out.
	Err error
	// Result is the response result when allowed, e.g. the signed event
	// JSON. For a decrypt it is plaintext: handle it as such.
	Result string
}

// Allowed reports whether the request was carried out.
func (d Decision) Allowed() bool { return d.Err == nil }

// ErrNoRelay means none of the relays could be reached.
var ErrNoRelay = errors.New("bunker: no relay could be reached")
