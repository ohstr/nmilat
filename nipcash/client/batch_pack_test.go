package client

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	btcec "github.com/flokiorg/go-flokicoin/crypto"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/utils"
)

func packTestKeypair(t *testing.T) (privHex, xonlyHex string) {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	privHex = hex.EncodeToString(priv.Serialize())
	pub, err := utils.GetPublicKey(privHex)
	if err != nil {
		t.Fatal(err)
	}
	return privHex, pub
}

// statusBuilders makes n cash_status builders, each for a different bill with its own
// key — the realistic multi-bill shape.
func statusBuilders(t *testing.T, n int) []itemBuilder {
	t.Helper()
	out := make([]itemBuilder, 0, n)
	for i := 0; i < n; i++ {
		priv, target := packTestKeypair(t)
		out = append(out, itemBuilder{
			ID: "i" + strconv.Itoa(i),
			Build: func(id string, b nipcash.ItemBinding) (transport.Item, error) {
				return nipcash.StatusItem(id, target, connSecretFor(target), nipcash.CashStatusParams{}, nipcash.BySigning(priv), b)
			},
		})
	}
	return out
}

// TestPackItems_EveryItemIsBoundToTheEnvelopeItTravelsIn is the property that makes
// splitting correct, and the one a naive implementation gets wrong.
//
// An item's proof commits to its envelope's NONCE. Split a batch after building
// proofs and every moved item is bound to a nonce it no longer travels under — which
// a hub answers with omission, information-free by design, so the caller never learns
// why their request vanished. Hence builders are deferred and items are constructed
// per envelope.
//
// Validate is the assertion: it checks exactly this binding, so a passing Validate on
// every produced envelope proves the property directly rather than by inspection.
func TestPackItems_EveryItemIsBoundToTheEnvelopeItTravelsIn(t *testing.T) {
	_, hub := packTestKeypair(t)

	// Small limits so the batch is forced across several envelopes.
	limits := transport.DefaultLimits()
	limits.MaxItems = 3

	packed, err := packItems(statusBuilders(t, 10), hub, limits, time.Minute)
	if err != nil {
		t.Fatalf("packItems() error = %v", err)
	}
	if len(packed) < 2 {
		t.Fatalf("expected the batch to split, got %d envelope(s)", len(packed))
	}

	seenNonces := map[string]struct{}{}
	total := 0
	for i, p := range packed {
		if err := p.Envelope.Validate(hub, time.Now()); err != nil {
			t.Errorf("envelope %d failed validation: %v — an item is bound to the wrong nonce", i, err)
		}
		if _, dup := seenNonces[p.Envelope.Nonce]; dup {
			t.Errorf("envelope %d reuses a nonce; each must be independently replay-checked", i)
		}
		seenNonces[p.Envelope.Nonce] = struct{}{}

		if len(p.ItemIDs) != len(p.Envelope.Items) {
			t.Errorf("envelope %d: %d ids for %d items", i, len(p.ItemIDs), len(p.Envelope.Items))
		}
		total += len(p.ItemIDs)
	}
	if total != 10 {
		t.Errorf("packed %d items, want 10 — splitting must not lose or duplicate any", total)
	}
}

// TestPackItems_RespectsAnnouncedLimits: packing must obey what the hub said, not a
// default, since a hub that lowered its limits would otherwise reject every envelope.
func TestPackItems_RespectsAnnouncedLimits(t *testing.T) {
	_, hub := packTestKeypair(t)

	for _, maxItems := range []int{1, 2, 5} {
		limits := transport.DefaultLimits()
		limits.MaxItems = maxItems

		packed, err := packItems(statusBuilders(t, 7), hub, limits, time.Minute)
		if err != nil {
			t.Fatalf("maxItems=%d: %v", maxItems, err)
		}
		for i, p := range packed {
			if len(p.Envelope.Items) > maxItems {
				t.Errorf("maxItems=%d: envelope %d carries %d items", maxItems, i, len(p.Envelope.Items))
			}
			// And it must genuinely encode under those limits, not merely look small.
			if _, err := p.Envelope.Encode(limits); err != nil {
				t.Errorf("maxItems=%d: envelope %d does not encode: %v", maxItems, i, err)
			}
		}
	}
}

// TestPackItems_PacksAsFewEnvelopesAsFit: one event instead of many is the entire
// point, so a batch that fits must not be split gratuitously.
func TestPackItems_PacksAsFewEnvelopesAsFit(t *testing.T) {
	_, hub := packTestKeypair(t)

	packed, err := packItems(statusBuilders(t, 8), hub, transport.DefaultLimits(), time.Minute)
	if err != nil {
		t.Fatalf("packItems() error = %v", err)
	}
	if len(packed) != 1 {
		t.Errorf("8 small items became %d envelopes; the default limits fit 32", len(packed))
	}
}

// TestPackItems_ASingleOversizeItemIsReportedNotLooped: an item too big for an empty
// envelope cannot be helped by splitting. It must error — not recurse forever, and not
// silently vanish into an unserved outcome the caller would misread as the hub's
// choice.
//
// Built by hand rather than from a params type, because the point is the packer's
// size path: packOne tests fit with Encode, which checks shape and size only.
func TestPackItems_ASingleOversizeItemIsReportedNotLooped(t *testing.T) {
	_, hub := packTestKeypair(t)
	limits := transport.DefaultLimits()

	huge := make([]byte, limits.MaxEnvelopeBytes+1024)
	for i := range huge {
		huge[i] = 'a'
	}
	params, err := json.Marshal(map[string]string{"filler": string(huge)})
	if err != nil {
		t.Fatal(err)
	}
	_, target := packTestKeypair(t)

	builders := append(statusBuilders(t, 1), itemBuilder{
		ID: "oversize",
		Build: func(id string, _ nipcash.ItemBinding) (transport.Item, error) {
			return transport.Item{
				ID: id, Target: target, Method: "cash_status",
				Params: params, Proof: json.RawMessage(`{"kind":23192}`),
			}, nil
		},
	})

	_, err = packItems(builders, hub, limits, time.Minute)
	if !errors.Is(err, ErrItemTooLarge) {
		t.Fatalf("packItems() error = %v, want ErrItemTooLarge", err)
	}
}

// TestPackItems_ABuilderErrorSurfaces: a caller's own mistake must not be laundered
// into an unserved outcome, where it would be indistinguishable from the hub
// declining to answer.
func TestPackItems_ABuilderErrorSurfaces(t *testing.T) {
	_, hub := packTestKeypair(t)

	builders := statusBuilders(t, 2)
	builders = append(builders, itemBuilder{
		ID: "bad",
		Build: func(string, nipcash.ItemBinding) (transport.Item, error) {
			return transport.Item{}, errors.New("credential cannot sign")
		},
	})

	if _, err := packItems(builders, hub, transport.DefaultLimits(), time.Minute); err == nil {
		t.Fatal("packItems() = nil error; a builder failure must surface to the caller")
	}
}

// connSecretFor mirrors the helper in nipcash's own tests: a deterministic,
// per-bill connection secret, so bill proofs are valid and no two bills share one.
func connSecretFor(target string) string {
	sum := sha256.Sum256([]byte("conn-secret:" + target))
	return hex.EncodeToString(sum[:])
}
