// Package nip01 implements NIP-01: the core event, filter, and subscription
// types every other package in this SDK builds on — event construction,
// signing, verification, and NIP-01 subscription filters.
package nip01

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
	"github.com/ohstr/nmilat/nip13"
	"github.com/ohstr/nmilat/utils"
)

type Event struct {
	ID        string     `json:"id"`
	PubKey    string     `json:"pubkey"`
	CreatedAt uint64     `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

// NewEvent builds an unsigned event. Sign() derives and overwrites PubKey
// from the signing key, so there is no pubkey parameter here — use
// NewSignedEvent if you have a private key and just want a publishable
// event in one call, or NewUnsignedEvent if the pubkey is known but signing
// happens elsewhere (e.g. a remote signer).
func NewEvent(kind int, content string, tags ...[]string) *Event {
	return &Event{
		Kind:      kind,
		Tags:      tags,
		CreatedAt: uint64(time.Now().Unix()),
		Content:   content,
	}
}

// NewSignedEvent builds an event and signs it with privateKey in one call —
// the common path for "I have a key and some content, give me a publishable
// event." Use NewEvent + Sign separately when you need to inspect or mutate
// the event between construction and signing (e.g. PoW mining via Mine).
func NewSignedEvent(kind int, content, privateKey string, tags ...[]string) (*Event, error) {
	ev := NewEvent(kind, content, tags...)
	if err := ev.Sign(privateKey); err != nil {
		return nil, err
	}
	return ev, nil
}

// NewUnsignedEvent builds an event for a signer that is not this process
// (e.g. NIP-46 remote signing, delegation). pubkey is not verified; Sign()
// will still overwrite it if this event is later signed locally.
func NewUnsignedEvent(kind int, pubkey, content string, tags ...[]string) *Event {
	return &Event{
		Kind:      kind,
		PubKey:    pubkey,
		Tags:      tags,
		CreatedAt: uint64(time.Now().Unix()),
		Content:   content,
	}
}

func (ev *Event) Validate() error {

	if err := utils.Validate32Key(ev.ID); err != nil {
		return fmt.Errorf("invalid event ID `%s`, %w", ev.ID, err)
	}

	if err := utils.Validate32Key(ev.PubKey); err != nil {
		return fmt.Errorf("invalid event pubKey `%s`, %w", ev.PubKey, err)
	}

	if err := utils.ValidateKind(ev.Kind); err != nil {
		return fmt.Errorf("invalid event kind `%d`, %w", ev.Kind, err)
	}

	return nil
}

func (ev *Event) HashID() ([]byte, error) {

	tagsBytes, err := utils.MarshalTags(ev.Tags)
	if err != nil {
		return nil, err
	}

	// Pre-size for the known/estimable parts (pubkey, tags, content, and
	// JSON scaffolding) so the appends below grow the buffer at most once,
	// instead of repeatedly doubling it — this runs on every Sign/Verify.
	str := make([]byte, 0, len(tagsBytes)+len(ev.Content)+96)
	str = fmt.Appendf(str, "[0,\"%s\",%d,%d,", strings.ToLower(ev.PubKey), ev.CreatedAt, ev.Kind)
	str = append(str, tagsBytes...)
	str = append(str, ',')
	str = fmt.Appendf(str, `"%s"`, utils.EscapeJSONString(ev.Content))
	str = append(str, ']')

	hsh := sha256.Sum256(str)

	return hsh[:], nil
}

// VerifyOption configures Verify's strictness. The zero value of every
// option is "off" -- Verify with no options performs its original check,
// unchanged: format, signature, ID, and (if a nonce tag is present) NIP-13
// proof-of-work.
type VerifyOption func(*verifyConfig)

type verifyConfig struct {
	skipPow bool
}

// WithoutPowCheck skips NIP-13 proof-of-work validation: an event carrying
// a nonce tag whose declared difficulty doesn't match its actual ID is
// accepted instead of rejected. Format/signature/ID checks are unaffected.
func WithoutPowCheck() VerifyOption {
	return func(c *verifyConfig) { c.skipPow = true }
}

// Verify fully verifies an untrusted event: format (via Validate) plus
// cryptographic signature/ID/PoW. Use Validate alone only when you
// deliberately want a cheap format-only pre-check ahead of a separate,
// more expensive verification pass.
func (ev *Event) Verify(opts ...VerifyOption) error {

	if err := ev.Validate(); err != nil {
		return err
	}

	var cfg verifyConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	if !cfg.skipPow {
		if _, ok := utils.LookupEventTag(ev.Tags, nip13.POWTagName); ok {
			fields := nip13.Fields{ID: ev.ID, PubKey: ev.PubKey, CreatedAt: ev.CreatedAt, Kind: ev.Kind, Tags: ev.Tags, Content: ev.Content}
			if _, _, err := nip13.ValidatePow(fields); err != nil {
				return fmt.Errorf("pow check failed: %w", err)
			}
		}
	}

	sigBytes, err := hex.DecodeString(ev.Sig)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	signature, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %w", err)
	}

	genEventIDBytes, err := ev.HashID()
	if err != nil {
		return fmt.Errorf("failed to generate ID from properties: %w", err)
	}

	genID := hex.EncodeToString(genEventIDBytes)
	if ev.ID != genID {
		return fmt.Errorf("event ID mismatch generated ID=%s", genID)
	}

	publicKeyBytes, err := hex.DecodeString(ev.PubKey)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %w", err)
	}

	pubkey, err := schnorr.ParsePubKey(publicKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	if !signature.Verify(genEventIDBytes, pubkey) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

func (ev *Event) Sign(privateKey string) error {

	privateKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return fmt.Errorf("invalid private key: %w", err)
	}

	privKey, pubKey := btcec.PrivKeyFromBytes(privateKeyBytes)
	publicKeyBytes := pubKey.SerializeCompressed()

	// set public key to the event
	ev.PubKey = hex.EncodeToString(publicKeyBytes[1:])

	genEventIDBytes, _ := ev.HashID()

	// sign it
	sig, err := schnorr.Sign(privKey, genEventIDBytes)
	if err != nil {
		return fmt.Errorf("failed to sign event: %w", err)
	}

	ev.ID = hex.EncodeToString(genEventIDBytes)
	ev.Sig = hex.EncodeToString(sig.Serialize())

	return nil
}

func (ev *Event) Copy() *Event {
	event := *ev

	if len(ev.Tags) > 0 {
		event.Tags = make([][]string, len(ev.Tags))
		for i, tag := range ev.Tags {
			event.Tags[i] = make([]string, len(tag))
			copy(event.Tags[i], tag)
		}
	}

	return &event
}

func (ev *Event) AddTag(tag []string) {
	ev.Tags = append(ev.Tags, tag)
}

// Rehash recomputes ev.ID from the event's current fields (does not sign).
// Use this after mutating Tags/Content/CreatedAt on an already-signed event
// so a later Verify() call sees an ID that actually matches the content,
// rather than one left stale from before the mutation.
func (ev *Event) Rehash() error {
	idBytes, err := ev.HashID()
	if err != nil {
		return err
	}
	ev.ID = hex.EncodeToString(idBytes)
	return nil
}

// Mine finds a NIP-13 proof-of-work nonce for ev with at least
// targetDifficulty leading zero bits, appending the winning nonce tag and
// setting ev.ID. ev must be unsigned — call this before Sign, never after,
// since mining changes ID and Sign would need to re-derive it anyway. opts
// configure the search itself (nip13.WithWorkers for parallelism,
// nip13.WithProgress for progress reporting); with none given this searches
// single-threaded, identical to before opts existed.
func (ev *Event) Mine(ctx context.Context, targetDifficulty int, opts ...nip13.MineOption) error {
	fields := nip13.Fields{PubKey: ev.PubKey, CreatedAt: ev.CreatedAt, Kind: ev.Kind, Tags: ev.Tags, Content: ev.Content, Sig: ev.Sig}
	id, nonceTag, err := nip13.Mine(ctx, fields, targetDifficulty, opts...)
	if err != nil {
		return err
	}
	ev.ID = id
	ev.Tags = append(ev.Tags, nonceTag)
	return nil
}

// GetTag returns every value recorded against tagName across ev's tags
// (e.g. GetTag("e") for an event with ["e", "id1"] and ["e", "id2"] tags
// returns ["id1", "id2"]), or nil if tagName doesn't appear.
func (e *Event) GetTag(tagName string) []string {
	var values []string
	for _, tag := range e.Tags {
		if len(tag) > 1 && tag[0] == tagName {
			values = append(values, tag[1:]...)
		}
	}
	if len(values) == 0 {
		return nil
	}
	return values
}
