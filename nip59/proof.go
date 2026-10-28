package nip59

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
)

// Proof shows what one seal's author wrote, to anyone: the seal and the
// message keys of its one payload. It reveals no conversation or private
// key, so it opens no other message.
type Proof struct {
	Seal *nip01.Event `json:"seal"`
	Keys nip44.Keys   `json:"keys"`
}

// MessageKeyer returns one NIP-44 payload's message keys; nip46.LocalKey and
// nipLS.Client implement it.
type MessageKeyer interface {
	MessageKeys(ctx context.Context, peerPubKey, payload string) (nip44.Keys, error)
}

// Prove builds a Proof for seal with the keys of a party to it: the
// recipient (counterpart = the seal's author) or the author (counterpart =
// the recipient).
func Prove(ctx context.Context, key MessageKeyer, seal *nip01.Event, counterpart string) (*Proof, error) {
	if seal.Kind != KindSeal {
		return nil, fmt.Errorf("nip59: kind %d is not a seal", seal.Kind)
	}
	if err := seal.Verify(nip01.WithoutPowCheck()); err != nil {
		return nil, fmt.Errorf("nip59: seal does not verify: %w", err)
	}
	keys, err := key.MessageKeys(ctx, counterpart, seal.Content)
	if err != nil {
		return nil, fmt.Errorf("nip59: message keys: %w", err)
	}
	return &Proof{Seal: seal, Keys: keys}, nil
}

// VerifyProof checks p with no private key and returns the rumor: the seal
// is a kind 13 signed by from, its MAC holds under p.Keys, it decrypts and
// unpads, and the rumor's id is its hash and its author is from.
//
// The MAC binds only the HMAC key: the ChaCha key and nonce can't be tied to
// the seal without the conversation key. What stops a forged reading is that
// any other keystream would have to turn the signed ciphertext into valid
// padding and rumor JSON naming from as author. Keep every one of those
// checks.
func VerifyProof(p *Proof, from string) (*nip01.Event, error) {
	if p == nil || p.Seal == nil {
		return nil, errors.New("nip59: proof has no seal")
	}
	if p.Seal.Kind != KindSeal {
		return nil, fmt.Errorf("nip59: kind %d is not a seal", p.Seal.Kind)
	}
	if err := p.Seal.Verify(nip01.WithoutPowCheck()); err != nil {
		return nil, fmt.Errorf("nip59: seal does not verify: %w", err)
	}
	if !strings.EqualFold(p.Seal.PubKey, from) {
		return nil, fmt.Errorf("nip59: seal is signed by %s, not %s", p.Seal.PubKey, from)
	}
	plain, err := nip44.OpenWithKeys(p.Keys, p.Seal.Content)
	if err != nil {
		return nil, fmt.Errorf("nip59: keys do not open the seal: %w", err)
	}
	return ParseRumor(plain, p.Seal.PubKey)
}
