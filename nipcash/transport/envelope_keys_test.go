package transport

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
)

// NIP-CASH §Envelopes and §Serving an Envelope: the nonce and not_after a Hub checks at E2 to E4 are the ones it
// runs and remembers. Keys are matched exactly; an envelope spelling one key twice, or two ways that differ only in
// case, is dropped, since a reader that folds case would see a different header.
func TestClassifyEnvelope_HeaderKeysAreMatchedExactly(t *testing.T) {
	item := `{"id":"1","target":"` + hex64("a") + `","method":"cash_status","params":{},"bill_proof":{"x":1}}`
	nonce, replayed, replyTo := hex64("1"), hex64("9"), hex64("2")
	soon := strconv.FormatInt(serveNow.Unix()+60, 10)
	far := strconv.FormatInt(serveNow.Unix()+1000*DefaultLimits().MaxRequestAgeSeconds, 10)
	head := `"nonce":"` + nonce + `","reply_to":"` + replyTo + `","not_after":` + soon + `,"items":[` + item + `]`
	seen := func(n string) bool { return n == replayed }
	run := func(body string) ServeVerdict {
		return ClassifyEnvelope([]byte("{"+body+"}"), nil, DefaultLimits(), serveNow, seen)
	}

	for name, body := range map[string]string{
		"Nonce beside nonce":         head + `,"Nonce":"` + replayed + `"`,
		"NOT_AFTER beside not_after": head + `,"NOT_AFTER":` + far,
		"nonce twice":                head + `,"nonce":"` + replayed + `"`,
		"not_after twice":            head + `,"not_after":` + far,
		"an escaped nonce twice":     head + `,"nonce":"` + replayed + `"`,
		"Reply_To beside reply_to":   head + `,"Reply_To":"` + hex64("3") + `"`,
		"ITEMS beside items":         head + `,"ITEMS":[]`,
		"a variant before the key":   `"NONCE":"` + replayed + `",` + head,
	} {
		if v := run(body); v.Action != ServeDrop || !errors.Is(v.Reason, ErrEnvelopeKeys) {
			t.Errorf("%s: %v %v, want a drop on ErrEnvelopeKeys", name, v.Action, v.Reason)
		}
	}

	// A variant alone is an unknown key: the exact key is what is missing, and a lone "Nonce" is never the nonce.
	if v := run(`"Nonce":"` + nonce + `","reply_to":"` + replyTo + `","not_after":` + soon + `,"items":[` + item + `]`); v.Action != ServeRefuse || v.Code != "BAD_REQUEST" {
		t.Errorf("Nonce alone: %v %s, want BAD_REQUEST", v.Action, v.Code)
	}
	if v := run(`"nonce":"` + nonce + `","reply_to":"` + replyTo + `","NOT_AFTER":` + soon + `,"items":[` + item + `]`); v.Action != ServeRefuse || v.Code != "BAD_REQUEST" {
		t.Errorf("NOT_AFTER alone: %v %s, want BAD_REQUEST", v.Action, v.Code)
	}

	// The exact keys run, with the header E2 to E4 checked; unknown keys and a padding variant are ignored.
	for name, body := range map[string]string{
		"the exact keys":    head,
		"an unknown key":    head + `,"extra":1`,
		"a Pad variant":     head + `,"Pad":"00"`,
		"pad and an extra":  head + `,"pad":"000","x":"y"`,
		"items not_after_x": head + `,"not_after_x":` + far,
	} {
		v := run(body)
		if v.Action != ServeRun || v.Envelope.Nonce != nonce || strconv.FormatInt(v.Envelope.NotAfter, 10) != soon || v.Envelope.ReplyTo != replyTo {
			t.Errorf("%s: %v %v %+v", name, v.Action, v.Reason, v.Envelope)
		}
	}
}

// Decode reads items by their exact keys too: an item repeating a key or spelling one two ways is omitted (I1), and
// a lone variant is an unknown key, so an item whose only "target" is "Target" has no target.
func TestDecode_ItemKeysAreMatchedExactly(t *testing.T) {
	target := `"target":"` + hex64("a") + `"`
	item := func(id, body string) string {
		return `{"id":"` + id + `",` + body + `,"method":"cash_status","bill_proof":{"x":1}}`
	}
	items := []string{
		item("ok", target+`,"params":{}`),
		item("unknown", target+`,"Params":{"a":1}`),
		item("Target", target+`,"Target":"`+hex64("b")+`"`),
		item("params twice", target+`,"params":{},"params":{"a":1}`),
		item("lone Target", `"Target":"`+hex64("a")+`"`),
	}
	plain := `{"nonce":"` + hex64("1") + `","reply_to":"` + hex64("2") + `","not_after":` +
		strconv.FormatInt(serveNow.Unix()+60, 10) + `,"items":[` + strings.Join(items, ",") + `]}`
	env, err := Decode([]byte(plain), DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, it := range env.Items {
		kept = append(kept, it.ID)
		if it.Target != hex64("a") {
			t.Errorf("item %s: target %s", it.ID, it.Target)
		}
		if it.ID == "unknown" && it.Params != nil {
			t.Errorf("a lone Params was read as params: %s", it.Params)
		}
	}
	if strings.Join(kept, ",") != "ok,unknown" || len(env.Rejected) != 3 {
		t.Fatalf("kept %v, rejected %d; want ok,unknown and 3 rejected", kept, len(env.Rejected))
	}

	var it Item
	if err := json.Unmarshal([]byte(`{"id":"1","ID":"2"}`), &it); !errors.Is(err, ErrEnvelopeKeys) {
		t.Errorf("Item with id and ID: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"ID":"2","proof":null}`), &it); err != nil || it.ID != "" || string(it.Proof) != "null" || it.HasProof() {
		t.Errorf("Item with ID alone: %v %+v", err, it)
	}
}
