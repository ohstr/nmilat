package transport

import (
	"encoding/json"
	"errors"
	"strconv"
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
	raw, err := json.Marshal(Envelope{NotAfter: notAfter, Nonce: nonce,
		ReplyTo: strings.Repeat("cd", 32), Items: items})
	if err != nil {
		t.Fatal(err)
	}
	return Decode(raw, DefaultLimits())
}

// T09-08: Decode keeps an item without a bill proof (the Hub omits it at I3, on
// its own terms) and its co-item; only I1 failures are omitted here.
func TestDecode_OneBadItemDoesNotDropItsCoItems(t *testing.T) {
	good, nonce, notAfter := perItemFixture(t, "1")
	bad := good
	bad.ID, bad.Target, bad.BillProof = "2", strings.Repeat("bb", 32), nil

	env, err := decodeItems(t, nonce, notAfter, good, bad)
	if err != nil {
		t.Fatalf("one item lacking a bill proof rejected the whole envelope: %v", err)
	}
	if len(env.Items) != 2 || env.Items[1].HasBillProof() {
		t.Fatalf("kept items = %d, want both, the second without a bill proof", len(env.Items))
	}
	same := good
	same.ID = "3"
	env, err = decodeItems(t, nonce, notAfter, good, same)
	if err != nil || len(env.Items) != 2 {
		t.Fatalf("two identical items: %v", err)
	}
}

// Two items sharing an id refuse the whole envelope (E4): a reply to that id
// could not say which one it answers.
func TestDecode_DuplicateIDsRefuseTheEnvelope(t *testing.T) {
	good, nonce, notAfter := perItemFixture(t, "1")
	a := good
	a.ID = "dup"
	b := good
	b.ID, b.Target = "dup", strings.Repeat("bb", 32)
	if _, err := decodeItems(t, nonce, notAfter, good, a, b); !errors.Is(err, ErrDuplicateItemID) {
		t.Fatalf("err = %v, want ErrDuplicateItemID", err)
	}
}

// An envelope whose every item is a structural omission still decodes, with no
// items: the Hub answers it with "results": [].
func TestDecode_NoServableItemStillDecodes(t *testing.T) {
	_, nonce, notAfter := perItemFixture(t, "1")
	raw := []byte(`{"not_after":` + strconv.FormatInt(notAfter, 10) + `,"nonce":"` + nonce + `","reply_to":"` + nonce +
		`","items":[{"id":1,"target":"x","method":"m"},"str"]}`)
	env, err := Decode(raw, DefaultLimits())
	if err != nil || len(env.Items) != 0 || len(env.Rejected) != 2 {
		t.Fatalf("Decode: %v %+v", err, env)
	}
}

// Encode stays strict: a client never builds an item the hub would drop.
func TestEncode_RefusesABadItem(t *testing.T) {
	good, nonce, notAfter := perItemFixture(t, "1")
	bad := good
	bad.ID, bad.Target, bad.BillProof = "2", strings.Repeat("bb", 32), nil
	env := Envelope{NotAfter: notAfter, Nonce: nonce,
		ReplyTo: strings.Repeat("cd", 32), Items: []Item{good, bad}}
	if _, err := env.Encode(DefaultLimits()); !errors.Is(err, ErrEnvelopeMalformed) {
		t.Fatalf("Encode err = %v, want ErrEnvelopeMalformed", err)
	}
}
