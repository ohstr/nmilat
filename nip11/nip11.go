// Package nip11 implements NIP-11: Relay Information Document, the
// application/nostr+json metadata a relay serves describing its name,
// supported NIPs, and connection limits.
package nip11

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/flokiorg/go-flokicoin/crypto"
	"github.com/rs/zerolog/log"
)

const (
	ContentTypeHeader = "application/nostr+json"
)

// NIPSet is an immutable, deduplicated, sorted collection of NIP numbers.
// It exists so the list served in a NIP-11 document can only ever be built
// through NewNIPSet/With, never assigned directly from caller-supplied config.
type NIPSet struct {
	nips []int
}

// NewNIPSet builds a NIPSet from the given NIP numbers, removing duplicates
// and sorting the result.
func NewNIPSet(nips ...int) NIPSet {
	seen := make(map[int]struct{}, len(nips))
	unique := make([]int, 0, len(nips))
	for _, n := range nips {
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		unique = append(unique, n)
	}
	sort.Ints(unique)
	return NIPSet{nips: unique}
}

// Slice returns a defensive copy of the underlying NIP numbers.
func (s NIPSet) Slice() []int {
	out := make([]int, len(s.nips))
	copy(out, s.nips)
	return out
}

// With returns a new NIPSet containing this set's NIPs plus the given ones,
// for composition roots that need to add NIPs the SDK itself has no
// visibility into (e.g. an application-level HTTP auth scheme).
func (s NIPSet) With(nips ...int) NIPSet {
	return NewNIPSet(append(s.Slice(), nips...)...)
}

type Metadata struct {
	Name        string `mapstructure:"name" json:"name"`
	PubKey      string `mapstructure:"pubkey" json:"pubkey"`
	Contact     string `mapstructure:"contact" json:"contact"`
	Description string `mapstructure:"description" json:"description"`
	// SupportedNips is intentionally not settable via config: it is only
	// ever populated by NewHandler from a derived NIPSet.
	SupportedNips []int      `mapstructure:"-" json:"supported_nips"`
	Software      string     `mapstructure:"software" json:"software"`
	Version       string     `mapstructure:"version" json:"version"`
	Limitation    Limitation `mapstructure:"limitation" json:"limitation"`

	// Operational fields, config-only. json:"-" makes it a type-level
	// guarantee that these never reach the wire, rather than relying on
	// every caller that marshals a Metadata value to remember to blank
	// them first (see NewHandler, which used to do exactly that).
	PrivKey    string            `mapstructure:"privkey" json:"-"`
	Delegation *DelegationConfig `mapstructure:"delegation" json:"-"`

	// URL is this relay's own canonical address, used to validate the
	// "relay" tag on incoming NIP-42 AUTH events. Not part of the NIP-11
	// document (json:"-").
	URL string `mapstructure:"url" json:"-"`
}

type DelegationConfig struct {
	Issuer     string `mapstructure:"issuer" json:"issuer"`
	Conditions string `mapstructure:"conditions" json:"conditions"`
	Token      string `mapstructure:"token" json:"token"`
}

type Limitation struct {
	// MaxLimit caps the "limit" field a client may request in a REQ filter;
	// requests above it are silently clamped down to this value.
	MaxLimit int `mapstructure:"max_limit" json:"max_limit"`

	// MaxMessageLength caps the size, in bytes, of a single incoming
	// WebSocket message (a REQ/EVENT/etc. frame) the relay will accept from
	// a client before closing the connection.
	MaxMessageLength int64 `mapstructure:"max_message_length" json:"max_message_length"`

	// MaxSubscriptions caps the number of concurrently open REQ
	// subscriptions a single connection may have.
	MaxSubscriptions int `mapstructure:"max_subscriptions" json:"max_subscriptions"`

	// MaxIndexableTags caps the number of tags per event that get written
	// to the tag index; tags beyond this are still stored with the event
	// but are not filterable by tag. Not part of the NIP-11 spec — an
	// nmilat-specific storage limit.
	MaxIndexableTags int `mapstructure:"max_indexable_tags" json:"max_indexable_tags"`

	// AuthRequired, if true, requires NIP-42 AUTH before the relay will
	// process REQ or EVENT from a connection.
	AuthRequired bool `mapstructure:"auth_required" json:"auth_required"`

	// MinPowDifficulty is the minimum NIP-13 leading-zero-bit difficulty
	// the relay wants, advertised so clients can mine ahead of time.
	// mapstructure:"-": not settable via nip11.limitation directly, so the
	// embedder's own config stays the single source of truth and copies its
	// value in here. Enforcement is StrictPow's job, not this field's.
	MinPowDifficulty int `mapstructure:"-" json:"min_pow_difficulty"`

	// StrictPow, if true, makes the relay reject (OK false, "pow: ...")
	// any event whose real difficulty (leading zero bits of its ID) falls
	// below MinPowDifficulty. If false, MinPowDifficulty is advisory only:
	// still advertised in the NIP-11 document, but under-difficulty events
	// are accepted anyway -- lets an operator announce a future
	// requirement before turning on rejection. json:"-": relay behavior,
	// not client-facing metadata. mapstructure:"-" for the same
	// single-source-of-truth reason as MinPowDifficulty.
	StrictPow bool `mapstructure:"-" json:"-"`
}

func NewHandler(md *Metadata, supported NIPSet) http.Handler {
	// PrivKey/Delegation are excluded from the marshaled output regardless
	// (json:"-" on Metadata) - this copy only needs to override
	// SupportedNips with the derived set rather than whatever md carries.
	publicMd := *md
	publicMd.SupportedNips = supported.Slice()

	metadataBytes, err := json.Marshal(publicMd)
	if err != nil {
		log.Fatal().Err(err).Msg("nip11 failed")
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("content-type", ContentTypeHeader)
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)
		w.Write(metadataBytes)
	})
}

func DerivePubKey(privHex string) (string, error) {
	b, err := hex.DecodeString(privHex)
	if err != nil {
		return "", err
	}
	if len(b) != 32 {
		return "", fmt.Errorf("invalid private key length")
	}

	_, pubKey := crypto.PrivKeyFromBytes(b)
	publicKeyBytes := pubKey.SerializeCompressed()
	return hex.EncodeToString(publicKeyBytes[1:]), nil
}
