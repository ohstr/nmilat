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
	"strconv"

	"github.com/flokiorg/go-flokicoin/crypto"
	"github.com/rs/zerolog/log"
)

const (
	ContentTypeHeader = "application/nostr+json"
)

// NIPID identifies a single NIP. Most NIPs are numbered (1, 9, 42) and are
// built with NIP; NIPs numbered past 99 that ran out of digits and continued
// with a letter suffix (NIP-B0, NIP-B7, NIP-C7, ...) are built with
// NIPLetter and carry their literal string ID rather than being coerced into
// a number. NIP-11 defines supported_nips as "an array of the integer
// identifiers of NIPs" but says nothing about the lettered ones, so those
// are serialized as JSON strings instead of being hex-decoded into an int
// that no other implementation would recognize.
type NIPID struct {
	n      int
	s      string
	letter bool
}

// NIP builds the ID for a plain numbered NIP (e.g. NIP(42) for NIP-42).
func NIP(n int) NIPID { return NIPID{n: n} }

// NIPLetter builds the ID for a letter-suffixed NIP (e.g. NIPLetter("B7")
// for NIP-B7).
func NIPLetter(s string) NIPID { return NIPID{s: s, letter: true} }

// String returns the NIP's canonical ID: a decimal number for a plain NIP,
// or the literal letter suffix (e.g. "B7") for a lettered one.
func (id NIPID) String() string {
	if id.letter {
		return id.s
	}
	return strconv.Itoa(id.n)
}

func (id NIPID) MarshalJSON() ([]byte, error) {
	if id.letter {
		return json.Marshal(id.s)
	}
	return json.Marshal(id.n)
}

func (id *NIPID) UnmarshalJSON(b []byte) error {
	var n int
	if err := json.Unmarshal(b, &n); err == nil {
		*id = NIPID{n: n}
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("nip11: NIP id must be a number or a string: %w", err)
	}
	*id = NIPID{s: s, letter: true}
	return nil
}

// NIPSet is an immutable, deduplicated, sorted collection of NIP IDs. It
// exists so the list served in a NIP-11 document can only ever be built
// through NewNIPSet/With, never assigned directly from caller-supplied
// config.
type NIPSet struct {
	nips []NIPID
}

// NewNIPSet builds a NIPSet from the given NIP IDs, removing duplicates and
// sorting the result: numbered NIPs first in ascending order, followed by
// lettered NIPs in alphabetical order.
func NewNIPSet(nips ...NIPID) NIPSet {
	seen := make(map[string]struct{}, len(nips))
	unique := make([]NIPID, 0, len(nips))
	for _, id := range nips {
		key := id.String()
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, id)
	}
	sort.Slice(unique, func(i, j int) bool {
		a, b := unique[i], unique[j]
		if a.letter != b.letter {
			return !a.letter
		}
		if a.letter {
			return a.s < b.s
		}
		return a.n < b.n
	})
	return NIPSet{nips: unique}
}

// Slice returns a defensive copy of the underlying NIP IDs.
func (s NIPSet) Slice() []NIPID {
	out := make([]NIPID, len(s.nips))
	copy(out, s.nips)
	return out
}

// With returns a new NIPSet containing this set's NIPs plus the given ones,
// for composition roots that need to add NIPs the SDK itself has no
// visibility into (e.g. an application-level HTTP auth scheme).
func (s NIPSet) With(nips ...NIPID) NIPSet {
	return NewNIPSet(append(s.Slice(), nips...)...)
}

type Metadata struct {
	Name        string `mapstructure:"name" json:"name"`
	PubKey      string `mapstructure:"pubkey" json:"pubkey"`
	Contact     string `mapstructure:"contact" json:"contact"`
	Description string `mapstructure:"description" json:"description"`
	// SupportedNips is intentionally not settable via config: it is only
	// ever populated by NewHandler from a derived NIPSet.
	SupportedNips []NIPID    `mapstructure:"-" json:"supported_nips"`
	Software      string     `mapstructure:"software" json:"software"`
	Version       string     `mapstructure:"version" json:"version"`
	Limitation    Limitation `mapstructure:"limitation" json:"limitation"`

	// PrivKey is operational, config-only. json:"-" makes it a type-level
	// guarantee that it never reaches the wire, rather than relying on
	// every caller that marshals a Metadata value to remember to blank it
	// first (see NewHandler, which used to do exactly that).
	PrivKey string `mapstructure:"privkey" json:"-"`

	// URL is this relay's own canonical address, used to validate the
	// "relay" tag on incoming NIP-42 AUTH events. Not part of the NIP-11
	// document (json:"-").
	URL string `mapstructure:"url" json:"-"`

	// Self is this relay's own signing identity, per NIP-11's "self"
	// field: "A relay MAY maintain an identity independent from its
	// administrator using the self field... This allows relays to respond
	// to requests with events published either in advance or on demand by
	// their own key." NIP-43's relay-authored events (role definitions,
	// membership lists, add/remove-user, invite responses) MUST be signed
	// by this pubkey.
	//
	// mapstructure:"-": not independently settable. This codebase's
	// initConfig already enforces PubKey == DerivePubKey(PrivKey) whenever
	// PrivKey is set, so there is only ever one operational signing
	// identity -- Self simply mirrors PubKey rather than adding a second,
	// potentially-divergent signing key. The embedder populates it only
	// when PrivKey is actually set (see ncli's initConfig), so a relay
	// that can't sign anything doesn't advertise a self identity nothing
	// can produce valid signatures for. json:"self,omitempty": omitted
	// from the NIP-11 document entirely when unset, matching the field's
	// own MAY/optional status.
	Self string `mapstructure:"-" json:"self,omitempty"`
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

	// MembershipRequired, if true, requires the connection to hold NIP-43
	// membership -- in addition to NIP-42 AUTH -- before the relay will
	// process REQ or EVENT. Directly config-settable, like AuthRequired:
	// unlike MinPowDifficulty/StrictPow below, there's no separate
	// advisory/strict split protecting a second source of truth here.
	MembershipRequired bool `mapstructure:"membership_required" json:"membership_required"`

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
	// PrivKey is excluded from the marshaled output regardless (json:"-"
	// on Metadata) - this copy only needs to override SupportedNips with
	// the derived set rather than whatever md carries.
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
