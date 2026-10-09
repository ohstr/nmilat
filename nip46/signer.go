package nip46

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip04"
	"github.com/ohstr/nmilat/nip19"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/utils"
)

// Signer signs events as one pubkey, wherever the key lives: in memory
// (*LocalKey), behind a unix socket (nipLS.Client) or a remote signer over
// relays (bunker.Client).
type Signer interface {
	// PubKey is the signing pubkey, lowercase hex.
	PubKey() string
	// Sign sets ev's PubKey, ID and Sig.
	Sign(ctx context.Context, ev *nip01.Event) error
}

// Key is a Signer that also runs the NIP-04/NIP-44 half of the method set.
// It is what a signer server signs and encrypts with. scheme is
// EncryptionNIP04 or EncryptionNIP44V2.
type Key interface {
	Signer
	Encrypt(ctx context.Context, scheme, peerPubKey, plaintext string) (string, error)
	Decrypt(ctx context.Context, scheme, peerPubKey, ciphertext string) (string, error)
}

var _ Key = (*LocalKey)(nil)

// LocalKey is a Key held in this process's memory.
type LocalKey struct {
	priv, pub string
}

// NewLocalKey wraps a private key given as hex or nsec.
func NewLocalKey(privKey string) (*LocalKey, error) {
	priv := strings.TrimSpace(privKey)
	if strings.HasPrefix(priv, "nsec1") {
		h, err := nip19.DecodePrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("nip46: invalid nsec: %w", err)
		}
		priv = h
	}
	priv = strings.ToLower(priv)
	if err := utils.Validate32Key(priv); err != nil {
		return nil, fmt.Errorf("nip46: invalid private key: %w", err)
	}
	pub, err := utils.GetPublicKey(priv)
	if err != nil {
		return nil, fmt.Errorf("nip46: invalid private key: %w", err)
	}
	return &LocalKey{priv: priv, pub: pub}, nil
}

// PubKey is the key's pubkey, lowercase hex.
func (k *LocalKey) PubKey() string { return k.pub }

// PrivKeyHex is the private key, lowercase hex. Servers need it for the
// transport encryption and to refuse output that leaks it.
func (k *LocalKey) PrivKeyHex() string { return k.priv }

// Sign sets ev's PubKey, ID and Sig.
func (k *LocalKey) Sign(_ context.Context, ev *nip01.Event) error {
	if ev.Tags == nil {
		ev.Tags = [][]string{}
	}
	return ev.Sign(k.priv)
}

// Encrypt encrypts plaintext to peerPubKey with scheme.
func (k *LocalKey) Encrypt(_ context.Context, scheme, peerPubKey, plaintext string) (string, error) {
	switch scheme {
	case EncryptionNIP04:
		return nip04.Encrypt(plaintext, k.priv, peerPubKey)
	case EncryptionNIP44V2:
		ck, err := k.conversationKey(peerPubKey)
		if err != nil {
			return "", err
		}
		return nip44.Encrypt(plaintext, ck)
	}
	return "", fmt.Errorf("%w: %q", ErrUnsupportedEncryption, scheme)
}

// Decrypt decrypts ciphertext from peerPubKey with scheme.
func (k *LocalKey) Decrypt(_ context.Context, scheme, peerPubKey, ciphertext string) (string, error) {
	switch scheme {
	case EncryptionNIP04:
		return nip04.Decrypt(ciphertext, peerPubKey, k.priv)
	case EncryptionNIP44V2:
		ck, err := k.conversationKey(peerPubKey)
		if err != nil {
			return "", err
		}
		return nip44.Decrypt(ciphertext, ck)
	}
	return "", fmt.Errorf("%w: %q", ErrUnsupportedEncryption, scheme)
}

func (k *LocalKey) conversationKey(peerPubKey string) ([]byte, error) {
	privBytes, err := hex.DecodeString(k.priv)
	if err != nil {
		return nil, err
	}
	priv, _ := btcec.PrivKeyFromBytes(privBytes)
	pubBytes, err := hex.DecodeString(peerPubKey)
	if err != nil {
		return nil, fmt.Errorf("invalid peer pubkey: %w", err)
	}
	pub, err := schnorr.ParsePubKey(pubBytes)
	if err != nil {
		return nil, fmt.Errorf("invalid peer pubkey: %w", err)
	}
	return nip44.GenerateConversationKey(priv, pub)
}

// MethodFor maps an encryption scheme and direction to its NIP-46 method.
func MethodFor(scheme string, encrypt bool) (string, error) {
	switch {
	case scheme == EncryptionNIP04 && encrypt:
		return MethodNIP04Encrypt, nil
	case scheme == EncryptionNIP04:
		return MethodNIP04Decrypt, nil
	case scheme == EncryptionNIP44V2 && encrypt:
		return MethodNIP44Encrypt, nil
	case scheme == EncryptionNIP44V2:
		return MethodNIP44Decrypt, nil
	}
	return "", fmt.Errorf("%w: %q", ErrUnsupportedEncryption, scheme)
}

// Wire error prefixes. A signer that starts a response error with one of
// these lets a client classify the refusal; see Error.
const (
	ErrPrefixDenied  = "denied: "
	ErrPrefixInvalid = "invalid: "
)

// ErrDenied and ErrInvalid classify a refused request; test with
// errors.Is. ErrDenied means the signer's policy (or a built-in safety
// check) refused it; ErrInvalid means the request was malformed.
var (
	ErrDenied  = errors.New("denied")
	ErrInvalid = errors.New("invalid")
)

// Error is a refusal with a reason. A policy returns one through Deny or
// Invalid; a client returns one for every error response.
type Error struct {
	// Code is ErrDenied, ErrInvalid, or nil for any other failure.
	Code   error
	Reason string
}

// Deny refuses a request.
func Deny(reason string) error { return &Error{Code: ErrDenied, Reason: reason} }

// Denyf is Deny with formatting.
func Denyf(format string, args ...any) error { return Deny(fmt.Sprintf(format, args...)) }

// Invalid rejects a request as malformed.
func Invalid(reason string) error { return &Error{Code: ErrInvalid, Reason: reason} }

func (e *Error) Error() string { return "nip46: " + e.Wire() }

// Unwrap lets errors.Is(err, ErrDenied) and errors.Is(err, ErrInvalid) work.
func (e *Error) Unwrap() error { return e.Code }

// Wire is the response "error" string for e.
func (e *Error) Wire() string {
	switch e.Code {
	case ErrDenied:
		return ErrPrefixDenied + e.Reason
	case ErrInvalid:
		return ErrPrefixInvalid + e.Reason
	}
	return e.Reason
}

// ParseError turns a response "error" string into an *Error.
func ParseError(msg string) *Error {
	if r, ok := strings.CutPrefix(msg, ErrPrefixDenied); ok {
		return &Error{Code: ErrDenied, Reason: r}
	}
	if r, ok := strings.CutPrefix(msg, ErrPrefixInvalid); ok {
		return &Error{Code: ErrInvalid, Reason: r}
	}
	return &Error{Reason: msg}
}

// WireError is the response "error" string for any error: an *Error's
// Wire form, otherwise the error's message.
func WireError(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Wire()
	}
	return err.Error()
}

// AsRefusal makes err a denial unless it already is an *Error.
func AsRefusal(err error) error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return Deny(err.Error())
}

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

// PrepareTarget sets ev's pubkey to signerPub, clears any signature, and
// computes the id the signature will cover.
func PrepareTarget(ev *nip01.Event, signerPub string) error {
	ev.PubKey, ev.ID, ev.Sig = strings.ToLower(signerPub), "", ""
	if ev.Tags == nil {
		ev.Tags = [][]string{}
	}
	id, err := ev.HashID()
	if err != nil {
		return fmt.Errorf("cannot hash event: %w", err)
	}
	ev.ID = hex.EncodeToString(id)
	return nil
}
