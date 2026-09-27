package nip59

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
)

// xOnlyHex returns a private key's 32-byte x-only pubkey hex, the form Nostr
// and NIP-44 use.
func xOnlyHex(priv *btcec.PrivateKey) string {
	compressed := priv.PubKey().SerializeCompressed()
	return hex.EncodeToString(compressed[1:])
}

func newTestKey(t *testing.T) (*btcec.PrivateKey, string) {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv, hex.EncodeToString(priv.Serialize())
}

// unwrapSeal peels the gift wrap and returns the seal event inside it.
func unwrapSeal(t *testing.T, wrap *nip01.Event, recipientPriv *btcec.PrivateKey) nip01.Event {
	t.Helper()
	ephemeralPubBytes, err := hex.DecodeString(wrap.PubKey)
	if err != nil {
		t.Fatalf("wrap pubkey: %v", err)
	}
	ephemeralPub, err := schnorr.ParsePubKey(ephemeralPubBytes)
	if err != nil {
		t.Fatalf("parse wrap pubkey: %v", err)
	}
	key, err := nip44.GenerateConversationKey(recipientPriv, ephemeralPub)
	if err != nil {
		t.Fatalf("conversation key: %v", err)
	}
	sealJSON, err := nip44.Decrypt(wrap.Content, key)
	if err != nil {
		t.Fatalf("decrypt wrap: %v", err)
	}
	var seal nip01.Event
	if err := json.Unmarshal([]byte(sealJSON), &seal); err != nil {
		t.Fatalf("unmarshal seal: %v", err)
	}
	return seal
}

// TestWrap_SealNeverCarriesAPrivateKey is the regression guard for a real
// landmine: Wrap used to assign the sender's PRIVATE key hex to seal.PubKey,
// relying on Sign to overwrite it a few lines later. It did, so nothing leaked —
// but any reordering, or a seal built without signing, would have published a
// private key inside a field designed to be public.
//
// Asserts the positive (PubKey is the sender's real x-only pubkey) and the
// negative (it is not the private key, nor contains it).
func TestWrap_SealNeverCarriesAPrivateKey(t *testing.T) {
	senderPriv, senderPrivHex := newTestKey(t)
	recipientPriv, _ := newTestKey(t)

	payload := nip01.NewEvent(1, "seal pubkey check")
	if err := payload.Sign(senderPrivHex); err != nil {
		t.Fatalf("sign payload: %v", err)
	}

	wrap, err := Wrap(payload, senderPrivHex, xOnlyHex(recipientPriv))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	seal := unwrapSeal(t, wrap, recipientPriv)

	if want := xOnlyHex(senderPriv); seal.PubKey != want {
		t.Errorf("seal.PubKey = %q, want the sender's x-only pubkey %q", seal.PubKey, want)
	}
	if seal.PubKey == senderPrivHex {
		t.Fatal("seal.PubKey is the sender's PRIVATE key — a private key is being published")
	}
	// Also check the serialized wrap: the private key must not appear anywhere,
	// in case a future field carries it by another route.
	raw, err := json.Marshal(wrap)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), senderPrivHex) {
		t.Fatal("the sender's private key appears in the serialized gift wrap")
	}
}

// TestRandomizedCreatedAt_InWindowAndVaries pins NIP-59's timestamp
// randomisation: within [now-2d, now], and actually varying rather than a
// constant that merely looks randomised.
func TestRandomizedCreatedAt_InWindowAndVaries(t *testing.T) {
	now := uint64(time.Now().Unix())
	earliest := now - uint64(maxCreatedAtBackdate.Seconds())

	seen := make(map[uint64]struct{})
	for i := 0; i < 200; i++ {
		got := RandomizedCreatedAt()
		// +1s of slack: now is sampled before the call.
		if got > now+1 || got < earliest {
			t.Fatalf("RandomizedCreatedAt() = %d, outside [%d, %d]", got, earliest, now)
		}
		seen[got] = struct{}{}
	}
	if len(seen) < 100 {
		t.Errorf("only %d distinct timestamps in 200 draws — not randomised", len(seen))
	}
}

// TestWrap_TimestampsAreBackdated checks the randomisation is actually applied
// to both layers. Before this, both carried the true time, which is exactly the
// correlation signal wrapping exists to remove.
//
// Probabilistic by nature, so it tests the aggregate: across many wraps, most
// must be meaningfully older than now. A single wrap can legitimately land near
// now.
func TestWrap_TimestampsAreBackdated(t *testing.T) {
	_, senderPrivHex := newTestKey(t)
	recipientPriv, _ := newTestKey(t)
	recipientXOnly := xOnlyHex(recipientPriv)

	payload := nip01.NewEvent(1, "timestamp check")
	if err := payload.Sign(senderPrivHex); err != nil {
		t.Fatal(err)
	}

	const runs = 40
	var backdatedWraps, backdatedSeals int
	for i := 0; i < runs; i++ {
		wrap, err := Wrap(payload, senderPrivHex, recipientXOnly)
		if err != nil {
			t.Fatalf("Wrap: %v", err)
		}
		now := uint64(time.Now().Unix())
		if wrap.CreatedAt+3600 < now {
			backdatedWraps++
		}
		if seal := unwrapSeal(t, wrap, recipientPriv); seal.CreatedAt+3600 < now {
			backdatedSeals++
		}
	}
	// Over a 2-day window, the chance of landing within the last hour is ~2%,
	// so requiring over half to be backdated is a very safe threshold while
	// still failing outright if randomisation is dropped.
	if backdatedWraps < runs/2 {
		t.Errorf("only %d/%d gift wraps were backdated — randomisation missing", backdatedWraps, runs)
	}
	if backdatedSeals < runs/2 {
		t.Errorf("only %d/%d seals were backdated — randomisation missing", backdatedSeals, runs)
	}
}

// TestWrap_WrongRecipientCannotDecrypt is the basic confidentiality property.
func TestWrap_WrongRecipientCannotDecrypt(t *testing.T) {
	_, senderPrivHex := newTestKey(t)
	recipientPriv, _ := newTestKey(t)
	strangerPriv, _ := newTestKey(t)

	payload := nip01.NewEvent(1, "for the recipient only")
	if err := payload.Sign(senderPrivHex); err != nil {
		t.Fatal(err)
	}
	wrap, err := Wrap(payload, senderPrivHex, xOnlyHex(recipientPriv))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}

	ephemeralPubBytes, _ := hex.DecodeString(wrap.PubKey)
	ephemeralPub, err := schnorr.ParsePubKey(ephemeralPubBytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := nip44.GenerateConversationKey(strangerPriv, ephemeralPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := nip44.Decrypt(wrap.Content, key); err == nil {
		t.Fatal("a stranger decrypted the gift wrap")
	}
}

// TestWrap_RejectsMalformedKeys pins that bad input fails loudly rather than
// producing an event nobody can open.
func TestWrap_RejectsMalformedKeys(t *testing.T) {
	_, senderPrivHex := newTestKey(t)
	recipientPriv, _ := newTestKey(t)
	payload := nip01.NewEvent(1, "x")
	if err := payload.Sign(senderPrivHex); err != nil {
		t.Fatal(err)
	}

	if _, err := Wrap(payload, "not-hex", xOnlyHex(recipientPriv)); err == nil {
		t.Error("expected an error for a non-hex sender key")
	}
	if _, err := Wrap(payload, senderPrivHex, "not-hex"); err == nil {
		t.Error("expected an error for a non-hex recipient key")
	}
	// A 33-byte compressed key is the classic mistake: NIP-44 wants 32-byte x-only.
	compressed := hex.EncodeToString(recipientPriv.PubKey().SerializeCompressed())
	if _, err := Wrap(payload, senderPrivHex, compressed); err == nil {
		t.Error("expected an error for a 33-byte compressed recipient key")
	}
}
