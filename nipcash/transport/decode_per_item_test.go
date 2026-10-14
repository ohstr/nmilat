package transport

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// perItemFixture builds one well-formed item and returns it with the envelope
// fields it binds to.
func perItemFixture(t *testing.T, id string) (Item, string, int64) {
	t.Helper()
	ph, err := CanonicalParamsHash(json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	nonce := strings.Repeat("ef", 32)
	b := ProofBinding{Target: strings.Repeat("aa", 32), HubXOnly: strings.Repeat("ab", 32),
		Method: "cash_status", ParamsHash: ph, Nonce: nonce, NotAfter: time.Now().Add(time.Minute).Unix()}
	bp, err := BuildBillProof(strings.Repeat("03", 32), b)
	if err != nil {
		t.Fatal(err)
	}
	ip, err := BuildItemProof(strings.Repeat("04", 32), b)
	if err != nil {
		t.Fatal(err)
	}
	return Item{ID: id, Target: b.Target, Method: "cash_status", Params: json.RawMessage(`{}`), Proof: ip, BillProof: bp},
		nonce, b.NotAfter
}

func decodeItems(t *testing.T, nonce string, notAfter int64, items ...Item) (*Envelope, error) {
	t.Helper()
	raw, err := json.Marshal(Envelope{Version: EnvelopeVersion, NotAfter: notAfter, Nonce: nonce,
		ReplyTo: strings.Repeat("cd", 32), Items: items})
	if err != nil {
		t.Fatal(err)
	}
	return Decode(raw, DefaultLimits())
}

// NIP-CASH §Batching Across Bills: "a Hub MUST evaluate each on its own". One
// item without a bill proof must not cost its co-item an answer.
func TestDecode_OneBadItemDoesNotDropItsCoItems(t *testing.T) {
	good, nonce, notAfter := perItemFixture(t, "1")
	bad := good
	bad.ID, bad.Target, bad.BillProof = "2", strings.Repeat("bb", 32), nil

	env, err := decodeItems(t, nonce, notAfter, good, bad)
	if err != nil {
		t.Fatalf("one item lacking a bill proof rejected the whole envelope: %v", err)
	}
	if len(env.Items) != 1 || env.Items[0].ID != "1" {
		t.Fatalf("kept items = %+v, want only item 1", env.Items)
	}
	if len(env.Rejected) != 1 || env.Rejected[0].Index != 1 || !errors.Is(env.Rejected[0].Err, ErrEnvelopeMalformed) {
		t.Fatalf("rejected = %+v, want item at index 1 as malformed", env.Rejected)
	}
}

// Two items sharing an id are both dropped: a reply to that id could not say
// which one it answers. Their co-item is still served.
func TestDecode_DuplicateIDsDropBothItems(t *testing.T) {
	good, nonce, notAfter := perItemFixture(t, "1")
	a := good
	a.ID, a.Params = "dup", json.RawMessage(`{"scope":"all"}`)
	b := good
	b.ID, b.Target = "dup", strings.Repeat("bb", 32)

	env, err := decodeItems(t, nonce, notAfter, good, a, b)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(env.Items) != 1 || env.Items[0].ID != "1" {
		t.Fatalf("kept items = %+v, want only item 1", env.Items)
	}
	for _, r := range env.Rejected {
		if !errors.Is(r.Err, ErrDuplicateItemID) {
			t.Fatalf("rejection %+v, want ErrDuplicateItemID", r)
		}
	}
}

// With no servable item left there is nothing to answer, so Decode fails with
// that item's own error, as it did before items were judged one by one.
func TestDecode_NoServableItemFailsWithItsError(t *testing.T) {
	good, nonce, notAfter := perItemFixture(t, "1")
	good.BillProof = nil
	if _, err := decodeItems(t, nonce, notAfter, good); !errors.Is(err, ErrEnvelopeMalformed) {
		t.Fatalf("err = %v, want ErrEnvelopeMalformed", err)
	}
}

// Encode stays strict: a client never builds an item the hub would drop.
func TestEncode_RefusesABadItem(t *testing.T) {
	good, nonce, notAfter := perItemFixture(t, "1")
	bad := good
	bad.ID, bad.Target, bad.BillProof = "2", strings.Repeat("bb", 32), nil
	env := Envelope{Version: EnvelopeVersion, NotAfter: notAfter, Nonce: nonce,
		ReplyTo: strings.Repeat("cd", 32), Items: []Item{good, bad}}
	if _, err := env.Encode(DefaultLimits()); !errors.Is(err, ErrEnvelopeMalformed) {
		t.Fatalf("Encode err = %v, want ErrEnvelopeMalformed", err)
	}
}
