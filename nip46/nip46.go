// Package nip46 implements NIP-46: Nostr Connect (remote signing), letting
// a client ask a remote signer to sign events, encrypt/decrypt payloads,
// or hand over a public key — over an encrypted request/response event
// pair (kind 24133) — instead of the client holding the private key
// itself.
//
// This package is the protocol layer only: building/parsing request and
// response events, encryption negotiation (NIP-04 legacy vs NIP-44), the
// standard method set, and the nostrconnect:// connection URI. It has no
// opinion on how a signer persists permissions, prompts a user for
// approval, or manages multiple client connections — that belongs to the
// consumer (e.g. a signer application) built on top of this package.
package nip46

import (
	"errors"
	"net/url"
)

// KindRequest is the event kind for both NIP-46 requests and responses —
// which one a given event is is determined by its decrypted content (a
// "method" field for a request, a "result"/"error" field for a response),
// not by its kind.
const KindRequest = 24133

// Standard NIP-46 method names, used as the "method" field of a Request.
// Params for each, per spec:
//
//	connect:        [signer-pubkey, optional secret, optional permissions]
//	sign_event:     [json-stringified unsigned event]
//	ping:           []
//	get_public_key: []
//	get_relays:     []
//	nip04_encrypt:  [recipient-pubkey, plaintext]
//	nip04_decrypt:  [sender-pubkey, ciphertext]
//	nip44_encrypt:  [recipient-pubkey, plaintext]
//	nip44_decrypt:  [sender-pubkey, ciphertext]
const (
	MethodConnect      = "connect"
	MethodSignEvent    = "sign_event"
	MethodPing         = "ping"
	MethodGetPublicKey = "get_public_key"
	MethodGetRelays    = "get_relays"
	MethodNIP04Encrypt = "nip04_encrypt"
	MethodNIP04Decrypt = "nip04_decrypt"
	MethodNIP44Encrypt = "nip44_encrypt"
	MethodNIP44Decrypt = "nip44_decrypt"
)

// Encryption scheme identifiers used in the request/response event's
// "encryption" tag. Absence of the tag implies EncryptionNIP04, per spec.
const (
	EncryptionNIP04   = "nip04"
	EncryptionNIP44V2 = "nip44_v2"
)

// Failure modes for the New*/Parse* functions in this package, for callers
// that need to distinguish them (e.g. via errors.Is) rather than match on
// message text.
var (
	ErrWrongKind             = errors.New("nip46: wrong kind")
	ErrUnsupportedEncryption = errors.New("nip46: unsupported encryption scheme")
)

// Metadata describes the connecting client application, carried in a
// nostrconnect:// URI's metadata query parameter.
type Metadata struct {
	Name        string `json:"name"`
	Url         string `json:"url"`
	Description string `json:"description"`
}

// NostrconnectSchema is a parsed nostrconnect:// connection URI.
type NostrconnectSchema struct {
	ClientPublickey string
	Metadata        *Metadata
	Relay           *url.URL
	Secret          string
}

// Request is the JSON shape of a decrypted request event's content.
//
// RequestID is named to avoid colliding with nip01.Event's own ID field
// when RequestEvent embeds both — RequestEvent.ID (event hash) and
// RequestEvent.RequestID (JSON-RPC correlation id) stay unambiguous.
type Request struct {
	RequestID string   `json:"id"`
	Method    string   `json:"method"`
	Params    []string `json:"params"`
}

// Response is the JSON shape of a decrypted response event's content.
// Result and Error are mutually exclusive — exactly one is set.
//
// RequestID (the id of the request this answers) is named to avoid
// colliding with nip01.Event's own ID field when ResponseEvent embeds
// both.
type Response struct {
	RequestID string `json:"id"`
	Result    string `json:"result,omitempty"`
	Error     string `json:"error,omitempty"`
}
