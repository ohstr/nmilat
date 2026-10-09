// Package nipLS implements NIP-LS: Local Signer, the NIP-46 method set
// spoken as newline-delimited JSON over a unix socket and addressed as
// bunker+unix:///abs/path.sock.
//
// A signer process holds the key; other processes on the same host or pod
// ask it to sign. There is no relay and no encryption: the socket's file
// permissions, plus an optional SO_PEERCRED uid/gid allow-list, decide who
// may connect, and a Policy decides what gets signed.
//
// Client side:
//
//	c, err := nipLS.Dial(ctx, "bunker+unix:///run/signer/agent.sock")
//	if err != nil { ... }
//	defer c.Close()
//	err = c.Sign(ctx, ev)
//	if errors.Is(err, nipLS.ErrDenied) { ... } // the policy refused
//
// Server side:
//
//	key, _ := nipLS.NewLocalKey(nsecOrHex)
//	srv, _ := nipLS.NewServer(nipLS.ServerConfig{Key: key, Policy: myPolicy})
//	err := srv.ListenAndServe(ctx, "/run/signer/agent.sock", nipLS.ListenOptions{Mode: 0o660})
//
// Both *Client and *LocalKey implement Signer, so code that signs can take
// either without caring where the key lives.
//
// Spec: https://github.com/ohstr/nips/blob/main/NIP-LS.md
package nipLS

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip19"
	"github.com/ohstr/nmilat/utils"
)

const (
	// URIScheme is the canonical signer URI scheme: bunker+unix:///abs/path.
	URIScheme = "bunker+unix"
	// uriSchemeShort is accepted on input as a synonym.
	uriSchemeShort = "unix"

	// MaxMessageSize bounds one request or response line, newline excluded.
	MaxMessageSize = 1 << 20

	// Wire error prefixes. A response error starting with one of these
	// maps to ErrDenied or ErrInvalid on the client.
	ErrPrefixDenied  = "denied: "
	ErrPrefixInvalid = "invalid: "
)

// ErrDenied and ErrInvalid classify a refused request; test with
// errors.Is. ErrDenied means the policy (or the built-in key guard)
// refused it; ErrInvalid means the request was malformed.
var (
	ErrDenied  = errors.New("denied")
	ErrInvalid = errors.New("invalid")
)

// Error is a refusal with a reason. Policies return one through Deny or
// Invalid; a Client returns one for every error response.
type Error struct {
	// Code is ErrDenied, ErrInvalid, or nil for any other failure.
	Code   error
	Reason string
}

// Deny refuses a request. Return it from Policy.Authorize.
func Deny(reason string) error { return &Error{Code: ErrDenied, Reason: reason} }

// Denyf is Deny with formatting.
func Denyf(format string, args ...any) error { return Deny(fmt.Sprintf(format, args...)) }

// Invalid rejects a request as malformed.
func Invalid(reason string) error { return &Error{Code: ErrInvalid, Reason: reason} }

func (e *Error) Error() string { return "nipLS: " + e.wire() }

// Unwrap lets errors.Is(err, ErrDenied) and errors.Is(err, ErrInvalid) work.
func (e *Error) Unwrap() error { return e.Code }

// wire is the response "error" string for e.
func (e *Error) wire() string {
	switch e.Code {
	case ErrDenied:
		return ErrPrefixDenied + e.Reason
	case ErrInvalid:
		return ErrPrefixInvalid + e.Reason
	}
	return e.Reason
}

// parseWireError turns a response "error" string into an *Error.
func parseWireError(msg string) *Error {
	if r, ok := strings.CutPrefix(msg, ErrPrefixDenied); ok {
		return &Error{Code: ErrDenied, Reason: r}
	}
	if r, ok := strings.CutPrefix(msg, ErrPrefixInvalid); ok {
		return &Error{Code: ErrInvalid, Reason: r}
	}
	return &Error{Reason: msg}
}

// IsURI reports whether s is written as a signer URI (bunker+unix:// or
// unix://), valid or not.
func IsURI(s string) bool {
	return strings.HasPrefix(s, URIScheme+"://") || strings.HasPrefix(s, uriSchemeShort+"://")
}

// ParseURI returns the socket path of a bunker+unix:// or unix:// URI. A
// bare absolute path is accepted too. The path must be absolute and carry
// no query or fragment.
func ParseURI(s string) (string, error) {
	path := s
	if rest, ok := strings.CutPrefix(s, URIScheme+"://"); ok {
		path = rest
	} else if rest, ok := strings.CutPrefix(s, uriSchemeShort+"://"); ok {
		path = rest
	} else if strings.Contains(s, "://") {
		return "", fmt.Errorf("nipLS: unsupported signer URI %q (want %s:///path/to.sock)", s, URIScheme)
	}
	if path == "" || !filepath.IsAbs(path) {
		return "", fmt.Errorf("nipLS: signer socket path must be absolute, got %q (want %s:///path/to.sock)", s, URIScheme)
	}
	if strings.ContainsAny(path, "?#") {
		return "", fmt.Errorf("nipLS: signer URI %q must not carry a query or fragment", s)
	}
	return filepath.Clean(path), nil
}

// FormatURI returns the bunker+unix:// URI for an absolute socket path.
func FormatURI(path string) string { return URIScheme + "://" + filepath.Clean(path) }

// ParsePubKey accepts an npub or 64-char hex pubkey and returns lowercase hex.
func ParsePubKey(s string) (string, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "npub1") {
		h, err := nip19.DecodePublicKey(s)
		if err != nil {
			return "", fmt.Errorf("invalid npub %q", s)
		}
		return strings.ToLower(h), nil
	}
	if err := utils.Validate32Key(s); err != nil {
		return "", fmt.Errorf("invalid pubkey %q (want npub or 64-char hex)", s)
	}
	return strings.ToLower(s), nil
}

// Signer signs events as one pubkey. *Client and *LocalKey implement it.
type Signer interface {
	// PubKey is the signing pubkey, lowercase hex.
	PubKey() string
	// Sign sets ev's PubKey, ID and Sig.
	Sign(ctx context.Context, ev *nip01.Event) error
}

// Key is what a Server signs and encrypts with. *LocalKey implements it
// for a key held in memory; *Client implements it too, so a Server can
// front another signer.
//
// scheme is nip46.EncryptionNIP04 or nip46.EncryptionNIP44V2.
type Key interface {
	Signer
	Encrypt(ctx context.Context, scheme, peerPubKey, plaintext string) (string, error)
	Decrypt(ctx context.Context, scheme, peerPubKey, ciphertext string) (string, error)
}

// Policy decides whether a sign_event, nip04_* or nip44_* request may
// proceed. Return nil to allow, Deny(reason) to refuse, or Invalid(reason)
// for a request the policy considers malformed; any other error refuses
// with its message as the reason.
//
// Authorize for sign_event runs under a server-wide lock, immediately
// before the key signs, so a policy can spend one-time state (an
// attestation, a quota) without racing another request.
type Policy interface {
	Authorize(ctx context.Context, req *Request) error
}

// PolicyFunc adapts a function to Policy.
type PolicyFunc func(ctx context.Context, req *Request) error

// Authorize calls f.
func (f PolicyFunc) Authorize(ctx context.Context, req *Request) error { return f(ctx, req) }

// AllowAll allows every request. Use it for tests or when the socket's
// permissions are the only gate you want.
var AllowAll Policy = PolicyFunc(func(context.Context, *Request) error { return nil })

// Request is one call as a Policy, a custom method Handler, or a decision
// hook sees it.
type Request struct {
	// ID is the client's request id.
	ID string
	// Method is the NIP-46 method name.
	Method string
	// Params are the raw request params.
	Params []string
	// Peer is the calling process.
	Peer Peer

	// Event is sign_event's event with PubKey and ID set to exactly what
	// the signature will cover. It is a copy: changing it has no effect.
	Event *nip01.Event
	// Attestations are events the client passed as sign_event's
	// params[1], for policies that require a third party's approval.
	Attestations []*nip01.Event

	// Counterpart is the nip04_*/nip44_* peer pubkey, lowercase hex.
	Counterpart string
	// Plaintext is set for nip04_encrypt and nip44_encrypt.
	Plaintext string
	// Ciphertext is set for nip04_decrypt and nip44_decrypt.
	Ciphertext string

	// Rule optionally names what decided, for the decision hook. A Policy
	// may set it.
	Rule string
}

// Decision reports one policy-gated request, or a refused connection
// (Request.Method empty), to ServerConfig.OnDecision.
type Decision struct {
	Time    time.Time
	Request *Request
	// Err is nil when the request was allowed and carried out.
	Err error
}

// Allowed reports whether the request was carried out.
func (d Decision) Allowed() bool { return d.Err == nil }

// Peer identifies the process on the other end of a connection, from
// SO_PEERCRED. Fields are nil where the platform can't tell.
type Peer struct {
	UID *int `json:"uid,omitempty"`
	GID *int `json:"gid,omitempty"`
	PID *int `json:"pid,omitempty"`
	// Conn numbers connections since the server started, so log lines stay
	// distinct when clients reuse request ids.
	Conn uint64 `json:"conn"`
}

// ErrPeerCredUnsupported is returned by NewServer when a uid/gid
// allow-list is set on a platform without SO_PEERCRED.
var ErrPeerCredUnsupported = errors.New("nipLS: uid/gid allow-lists need SO_PEERCRED, which is only supported on Linux")
