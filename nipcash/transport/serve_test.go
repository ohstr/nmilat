package transport

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip13"
	"github.com/ohstr/nmilat/nip44"
)

var serveNow = time.Unix(1720000000, 0)

func hex64(c string) string { return strings.Repeat(c, 64) }

// rawEnvelope builds a plaintext, items given as raw JSON.
func rawEnvelope(fields map[string]any) []byte {
	b, _ := json.Marshal(fields)
	return b
}

func baseFields(items ...json.RawMessage) map[string]any {
	if items == nil {
		items = []json.RawMessage{json.RawMessage(`{"id":"1","target":"` + hex64("a") + `","method":"cash_status","params":{},"proof":{"x":1},"bill_proof":{"x":1}}`)}
	}
	return map[string]any{"nonce": hex64("1"), "reply_to": hex64("2"), "not_after": serveNow.Unix() + 60, "items": items}
}

func classify(t *testing.T, fields map[string]any, seen NonceSeen) ServeVerdict {
	t.Helper()
	return ClassifyEnvelope(rawEnvelope(fields), nil, DefaultLimits(), serveNow, seen)
}

// T09-01..T09-06, T09-18, T09-26.
func TestClassifyEnvelope(t *testing.T) {
	if v := ClassifyEnvelope(nil, errors.New("bad mac"), DefaultLimits(), serveNow, nil); v.Action != ServeDrop {
		t.Error("E1 undecryptable")
	}
	if v := ClassifyEnvelope([]byte(`[1]`), nil, DefaultLimits(), serveNow, nil); v.Action != ServeDrop {
		t.Error("E1 not an object")
	}
	for name, edit := range map[string]func(map[string]any){
		"no reply_to": func(f map[string]any) { delete(f, "reply_to") },
		"63 reply_to": func(f map[string]any) { f["reply_to"] = hex64("2")[:63] },
		"not_after-1": func(f map[string]any) { f["not_after"] = serveNow.Unix() - 1 },
	} {
		f := baseFields()
		edit(f)
		if v := classify(t, f, nil); v.Action != ServeDrop {
			t.Errorf("%s: %v", name, v.Action)
		}
	}
	f := baseFields()
	f["not_after"] = serveNow.Unix()
	if v := classify(t, f, nil); v.Action != ServeRun {
		t.Errorf("E2 not_after = now: %+v", v)
	}
	if v := classify(t, baseFields(), func(n string) bool { return n == hex64("1") }); v.Action != ServeDrop {
		t.Error("E3 served nonce")
	}
	// E4: v ignored; refusals leave the nonce unserved (the caller marks only Run).
	for _, ver := range []any{2, nil} {
		f := baseFields()
		if ver != nil {
			f["v"] = ver
		}
		if v := classify(t, f, nil); v.Action != ServeRun {
			t.Errorf("v %v: %+v", ver, v)
		}
	}
	item := json.RawMessage(`{"id":"1","target":"` + hex64("a") + `","method":"cash_status","bill_proof":{"x":1}}`)
	for name, edit := range map[string]func(map[string]any){
		"uppercase nonce":    func(f map[string]any) { f["nonce"] = strings.ToUpper(hex64("a")) },
		"no not_after":       func(f map[string]any) { delete(f, "not_after") },
		"not_after 1.5":      func(f map[string]any) { f["not_after"] = json.RawMessage(`1720000060.0`) },
		"not_after string":   func(f map[string]any) { f["not_after"] = "x" },
		"not_after past H":   func(f map[string]any) { f["not_after"] = serveNow.Unix() + DefaultMaxRequestAge + 1 },
		"items empty":        func(f map[string]any) { f["items"] = []json.RawMessage{} },
		"items not an array": func(f map[string]any) { f["items"] = "x" },
		"two ids 1":          func(f map[string]any) { f["items"] = []json.RawMessage{item, item} },
	} {
		f := baseFields()
		edit(f)
		v := classify(t, f, nil)
		if v.Action != ServeRefuse || v.Code != "BAD_REQUEST" || v.Served {
			t.Errorf("%s: %+v", name, v)
		}
	}
	f = baseFields()
	f["not_after"] = serveNow.Unix() + DefaultMaxRequestAge
	if v := classify(t, f, nil); v.Action != ServeRun {
		t.Errorf("not_after now+H: %+v", v)
	}
	// E5.
	l := DefaultLimits()
	l.MaxItems = 10
	var many []json.RawMessage
	for i := range 11 {
		many = append(many, json.RawMessage(`{"id":"`+strconv.Itoa(i)+`","target":"`+hex64("a")+`","method":"cash_status","bill_proof":{"x":1}}`))
	}
	if v := ClassifyEnvelope(rawEnvelope(baseFields(many...)), nil, l, serveNow, nil); v.Code != "QUOTA_EXCEEDED" || !v.Served {
		t.Errorf("11 items: %+v, want QUOTA_EXCEEDED with the nonce served", v)
	}
	if v := ClassifyEnvelope(rawEnvelope(baseFields(many[:10]...)), nil, l, serveNow, nil); v.Action != ServeRun {
		t.Errorf("10 items: %+v", v)
	}
	big := baseFields()
	big["pad"] = strings.Repeat("0", DefaultLimits().MaxEnvelopeBytes)
	if v := classify(t, big, nil); v.Code != "QUOTA_EXCEEDED" {
		t.Errorf("over max_bytes: %+v", v)
	}
	// E6: budget 8 against 7.
	l = DefaultLimits()
	l.MaxVerifyBudget = 7
	pubkeyRedeem := json.RawMessage(`{"id":"r","target":"` + hex64("a") + `","method":"cash_redeem","params":{"identity_event":"{}"},"proof":{"x":1},"bill_proof":{"x":1}}`)
	ckTransfer := json.RawMessage(`{"id":"t","target":"` + hex64("b") + `","method":"cash_transfer","params":{"identity_event":"{}","attestation_event":"{}"},"proof":{"x":1},"bill_proof":{"x":1}}`)
	bearer := json.RawMessage(`{"id":"b","target":"` + hex64("c") + `","method":"cash_redeem","params":{"cash_secret":"s"},"bill_proof":{"x":1}}`)
	eight := baseFields(pubkeyRedeem, ckTransfer, bearer)
	if v := ClassifyEnvelope(rawEnvelope(eight), nil, l, serveNow, nil); v.Code != "QUOTA_EXCEEDED" || !v.Served {
		t.Errorf("budget 8 vs 7: %+v, want QUOTA_EXCEEDED with the nonce served", v)
	}
	l.MaxVerifyBudget = 8
	if v := ClassifyEnvelope(rawEnvelope(eight), nil, l, serveNow, nil); v.Action != ServeRun {
		t.Errorf("budget 8 vs 8: %+v", v)
	}
}

// T09-07 (K-VB-1).
func TestKVB1_VerificationCost(t *testing.T) {
	item := func(params string, proof bool) Item {
		it := Item{Params: json.RawMessage(params), BillProof: json.RawMessage(`{}`)}
		if proof {
			it.Proof = json.RawMessage(`{}`)
		}
		return it
	}
	for name, tc := range map[string]struct {
		it   Item
		want int
	}{
		"pubkey redeem":       {item(`{"identity_event":"{}"}`, true), 3},
		"bearer redeem":       {item(`{"cash_secret":"s"}`, false), 1},
		"CK transfer":         {item(`{"identity_event":"{}","attestation_event":"{}"}`, true), 4},
		"consolidate 3":       {item(`{"sources":[{"identity_event":"{}"},{"identity_event":"{}"},{"identity_event":"{}"}]}`, true), 5},
		"consolidate 2+CK":    {item(`{"sources":[{"identity_event":"{}"},{"identity_event":"{}"},{"identity_event":"{}","attestation_event":"{}"}]}`, true), 6},
		"signed status":       {item(`{}`, true), 2},
		"cash-mode status":    {item(`{}`, false), 1},
		"private join":        {item(`{"identity_event":{"kind":23199}}`, true), 3},
		"withdraw with quote": {item(`{"identity_event":"{}","quote":{"kind":23187}}`, true), 4},
	} {
		if got := tc.it.VerificationCost(); got != tc.want {
			t.Errorf("%s: %d, want %d", name, got, tc.want)
		}
	}
}

// T09-08, T09-09.
func TestDecode_KeepsAndOmits(t *testing.T) {
	l := DefaultLimits()
	l.MaxConsolidateSources = 2
	items := []json.RawMessage{
		json.RawMessage(`{"id":"s","target":"` + hex64("a") + `","method":"cash_status"}`),
		json.RawMessage(`{"id":"n","target":"` + hex64("a") + `","method":"cash_status","bill_proof":null}`),
		json.RawMessage(`{"id":"c","target":"` + hex64("b") + `","method":"cash_consolidate","params":{"sources":[{},{},{}]}}`),
		json.RawMessage(`"not an object"`),
		json.RawMessage(`{"id":5,"target":"x","method":"m"}`),
		json.RawMessage(`{"id":"p","target":"x","method":"m","params":[1]}`),
	}
	env, err := Decode(rawEnvelope(baseFields(items...)), l)
	if err != nil {
		t.Fatal(err)
	}
	if len(env.Items) != 2 || env.Items[1].HasBillProof() {
		t.Fatalf("kept %d items", len(env.Items))
	}
	codes := map[int]string{}
	for _, r := range env.Rejected {
		codes[r.Index] = r.Code
	}
	if codes[2] != "QUOTA_EXCEEDED" || len(env.Rejected) != 4 {
		t.Errorf("rejections %+v", env.Rejected)
	}
}

// T09-10 (K-PAD-1), T09-12.
func TestKPAD1_Padding(t *testing.T) {
	l := DefaultLimits()
	l.PadBucketBytes, l.MaxEnvelopeBytes = 4096, 56*1024
	if got, _ := l.PaddedSize(5000); got != 8192 {
		t.Errorf("bucket 4096, 5000 → %d", got)
	}
	l.MaxEnvelopeBytes = 6000
	if got, _ := l.PaddedSize(5000); got != 6000 {
		t.Errorf("max_bytes 6000 → %d", got)
	}
	if _, err := l.PaddedSize(6001); !errors.Is(err, ErrEnvelopeTooLarge) {
		t.Error("over max_bytes padded")
	}
	if got, _ := PaddedReplySize(5000, 4096); got != 8192 {
		t.Errorf("reply %d", got)
	}
	if got, _ := PaddedReplySize(65000, 4096); got != 65535 {
		t.Errorf("reply ceiling %d", got)
	}
	// A reply bigger than the request's max_bytes still encodes.
	small := DefaultLimits()
	small.MaxEnvelopeBytes = 4096
	small.PadBucketBytes = 2048
	small.MaxConsolidateSources = 2
	r := ResponseEnvelope{ReqNonce: hex64("1"), Results: []Result{{ID: "1", ResultType: "cash_status", Result: json.RawMessage(`"` + strings.Repeat("x", 6000) + `"`)}}}
	enc, err := r.EncodeResponse(small)
	if err != nil || len(enc)%2048 != 0 {
		t.Fatalf("reply over max_bytes: %d %v", len(enc), err)
	}
}

// T09-11.
func TestEncodeResponse_ResultsKey(t *testing.T) {
	enc, _ := ResponseEnvelope{ReqNonce: hex64("1")}.EncodeResponse(DefaultLimits())
	if !strings.Contains(string(enc), `"results":[]`) || strings.Contains(string(enc), `"v"`) {
		t.Errorf("%s", enc[:60])
	}
	enc, _ = ResponseEnvelope{ReqNonce: hex64("1"), Error: &ResultError{Code: "QUOTA_EXCEEDED"}}.EncodeResponse(DefaultLimits())
	if strings.Contains(string(enc), `"results"`) {
		t.Error("an error reply carries results")
	}
}

// T09-13.
func TestWrapResponseChunk(t *testing.T) {
	var key [32]byte
	copy(key[:], strings.Repeat("k", 32))
	a, err := WrapResponseChunk([]byte(`{"x":1}`), key, hex64("2"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := WrapResponseChunk([]byte(`{"x":1}`), key, hex64("2"))
	now := uint64(time.Now().Unix())
	for _, ev := range []*nip01.Event{a, b} {
		if len(ev.Tags) != 1 || ev.Tags[0][0] != "p" || ev.Tags[0][1] != hex64("2") || ev.Kind != KindPrivateResponse {
			t.Errorf("tags %v", ev.Tags)
		}
		if ev.CreatedAt > now || ev.CreatedAt < now-2*86400 {
			t.Errorf("created_at %d", ev.CreatedAt)
		}
		if pt, err := nip44.Decrypt(ev.Content, key[:]); err != nil || pt != `{"x":1}` {
			t.Errorf("decrypt %v", err)
		}
		if err := ev.Verify(); err != nil {
			t.Error(err)
		}
	}
	if a.PubKey == b.PubKey {
		t.Error("chunk keys are not fresh")
	}
	if _, err := WrapResponseChunk(nil, key, "short"); err == nil {
		t.Error("bad reply_to wrapped")
	}
}

// T09-16, T09-20, T09-22, T09-27, T09-29.
func TestAllowlistAndBearerShape(t *testing.T) {
	for _, m := range []string{"cash_lookup", "cash_order", "cash_withdraw_quote", "cash_withdraw", "cash_status", "create_circle_wallet"} {
		if !IsServableMethod(m) {
			t.Errorf("%s not servable", m)
		}
	}
	for _, m := range []string{"mint_cash", "pay_invoice", "get_balance", "create_connection"} {
		if IsServableMethod(m) {
			t.Errorf("%s servable", m)
		}
	}
	type c struct {
		m           string
		proof, secr bool
		want        bool
	}
	for _, tc := range []c{
		{"cash_redeem", true, true, false}, {"cash_status", false, false, true}, {"cash_redeem", false, false, false},
		{"cash_transfer", false, false, false}, {"cash_consolidate", false, false, false}, {"cash_redeem", false, true, true},
		{"cash_status", false, true, false}, {"cash_status", true, true, false}, {"cash_order", false, false, false},
		{"cash_order", true, false, true}, {"cash_withdraw_quote", false, false, true}, {"cash_withdraw_quote", true, false, true},
		{"cash_withdraw_quote", false, true, false}, {"cash_withdraw_quote", true, true, false}, {"cash_withdraw", false, false, false},
		{"cash_withdraw", false, true, true}, {"cash_withdraw", true, false, true}, {"cash_lookup", false, false, true},
	} {
		if BearerShapeOK(tc.m, tc.proof, tc.secr) != tc.want {
			t.Errorf("BearerShapeOK(%s, proof %v, secret %v) != %v", tc.m, tc.proof, tc.secr, tc.want)
		}
	}
}

// T09-23.
func TestRelayPowMinimum(t *testing.T) {
	var gotAccept, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept, gotPath = r.Header.Get("Accept"), r.URL.Path
		switch r.URL.Path {
		case "/x":
			_, _ = w.Write([]byte(`{"limitation":{"min_pow_difficulty":20}}`))
		case "/none":
			_, _ = w.Write([]byte(`{}`))
		case "/500":
			w.WriteHeader(500)
		default:
			_, _ = w.Write([]byte(`not json`))
		}
	}))
	defer srv.Close()
	ws := "ws" + strings.TrimPrefix(srv.URL, "http")
	ctx := context.Background()
	if n, err := RelayPowMinimum(ctx, ws+"/x"); err != nil || n != 20 || gotAccept != "application/nostr+json" || gotPath != "/x" {
		t.Errorf("20: %d %v %q", n, err, gotAccept)
	}
	if n, err := RelayPowMinimum(ctx, ws+"/none"); err != nil || n != 0 {
		t.Errorf("absent: %d %v", n, err)
	}
	for _, p := range []string{"/500", "/junk"} {
		if _, err := RelayPowMinimum(ctx, ws+p); err == nil {
			t.Errorf("%s: no error", p)
		}
	}
}

// T09-24, T09-25 (K-POW-1..3).
func TestWrapRequestPow(t *testing.T) {
	_, inbox := testKeypair(t)
	ctx := context.Background()
	notAfter := time.Now().Unix() + 60
	r, key, err := WrapRequestPow(ctx, []byte(`{"a":1}`), inbox, notAfter, 12)
	if err != nil {
		t.Fatal(err)
	}
	ev := r.Event
	if len(ev.Tags) != 3 || ev.Tags[0][0] != "p" || ev.Tags[1][0] != "expiration" || ev.Tags[1][1] != strconv.FormatInt(notAfter, 10) ||
		ev.Tags[2][0] != "nonce" || ev.Tags[2][2] != "12" {
		t.Fatalf("tags %v", ev.Tags)
	}
	if d, _ := nip13.Difficulty(ev.ID); d < 12 {
		t.Errorf("difficulty %d", d)
	}
	if pt, err := nip44.Decrypt(ev.Content, key[:]); err != nil || pt != `{"a":1}` {
		t.Errorf("decrypt: %v", err)
	}
	before := *ev
	beforeTags := append([][]string(nil), ev.Tags...)
	if err := r.Remine(ctx, 14); err != nil {
		t.Fatal(err)
	}
	if ev.PubKey != before.PubKey || ev.Content != before.Content || ev.CreatedAt != before.CreatedAt ||
		ev.Tags[0][1] != beforeTags[0][1] || ev.Tags[1][1] != beforeTags[1][1] || ev.ID == before.ID {
		t.Error("Remine changed more than the nonce")
	}
	if d, _ := nip13.Difficulty(ev.ID); d < 14 || ev.Verify() != nil {
		t.Errorf("remined difficulty %d", d)
	}
	if _, _, err := WrapRequestPow(ctx, []byte(`x`), inbox, time.Now().Unix()+MaxPowAhead+5, 1); !errors.Is(err, ErrPowDeadline) {
		t.Errorf("far deadline: %v", err)
	}
	if _, _, err := WrapRequestPow(ctx, []byte(`x`), inbox, notAfter, 0); !errors.Is(err, ErrPowDifficulty) {
		t.Errorf("difficulty 0: %v", err)
	}
	for msg, want := range map[string][2]any{
		"pow: difficulty 20 required": {20, true}, "pow: too low": {0, true}, "blocked: no": {0, false},
	} {
		n, ok := ParsePowRejection(msg)
		if n != want[0].(int) || ok != want[1].(bool) {
			t.Errorf("%q → %d %v", msg, n, ok)
		}
	}
	if d, _ := nip13.Difficulty("000006d8c378af1779d2feebc7603a125d99eca0ccf1085959b307f64e5dd358"); d != 21 {
		t.Errorf("K-POW-1 %d", d)
	}
}

// T09-31.
func TestVerifyBillProofAny(t *testing.T) {
	priv1, b := testBinding(t)
	priv2, _ := testKeypair(t)
	pub1 := mustPub(t, priv1)
	pub2 := mustPub(t, priv2)
	proof2, _ := BuildBillProof(priv2, b)
	if i, err := VerifyBillProofAny(proof2, b, time.Now(), []string{pub1, pub2}); err != nil || i != 1 {
		t.Errorf("second connection: %d %v", i, err)
	}
	if _, err := VerifyBillProofAny(proof2, b, time.Now(), []string{pub1}); !errors.Is(err, ErrBillProofSigner) {
		t.Errorf("revoked: %v", err)
	}
	if _, err := VerifyBillProofAny(proof2, b, time.Now(), nil); !errors.Is(err, ErrBillProofSigner) {
		t.Errorf("empty live: %v", err)
	}
	other := b
	other.Method = "x"
	if _, err := VerifyBillProofAny(proof2, other, time.Now(), []string{pub2}); err == nil || errors.Is(err, ErrBillProofSigner) {
		t.Errorf("failing proof: %v", err)
	}
}

// F-ENV-1: no panic; a Drop never yields an envelope to mark; a Refuse never
// marks anything (the caller marks only Run).
func FuzzClassifyEnvelope(f *testing.F) {
	f.Add(rawEnvelope(baseFields()))
	f.Add([]byte(`{"reply_to":"` + hex64("2") + `","nonce":"x","items":[]}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		v := ClassifyEnvelope(data, nil, DefaultLimits(), serveNow, nil)
		switch v.Action {
		case ServeDrop:
			if v.Envelope != nil {
				t.Fatal("a dropped envelope came back")
			}
		case ServeRefuse:
			if v.Code != "BAD_REQUEST" && v.Code != "QUOTA_EXCEEDED" {
				t.Fatalf("code %q", v.Code)
			}
		case ServeRun:
			if v.Envelope == nil || len(v.Envelope.Nonce) != 64 {
				t.Fatal("run without a well-formed nonce")
			}
		}
	})
}

// F-CANON-1.
func FuzzCanonicalParamsHash(f *testing.F) {
	f.Add(`{"b":1,"a":[1,2,{"z":"<"}]}`)
	f.Fuzz(func(t *testing.T, s string) {
		h1, err := CanonicalParamsHash(json.RawMessage(s))
		if err != nil {
			return
		}
		var v any
		if json.Unmarshal([]byte(s), &v) != nil {
			return
		}
		// Re-indenting changes whitespace only.
		var buf bytes.Buffer
		_ = json.Indent(&buf, []byte(s), "", "  ")
		if h2, err := CanonicalParamsHash(json.RawMessage(buf.String())); err == nil && h2 != h1 {
			t.Fatalf("whitespace changed the hash: %s", s)
		}
	})
}

// F-POW-1.
func FuzzParsePowRejection(f *testing.F) {
	f.Add("pow: difficulty 20 required")
	f.Fuzz(func(t *testing.T, s string) {
		n, ok := ParsePowRejection(s)
		if ok != strings.HasPrefix(s, "pow:") || n < 0 {
			t.Fatalf("%q → %d %v", s, n, ok)
		}
	})
}

func mustPub(t *testing.T, priv string) string {
	t.Helper()
	b, _ := hex.DecodeString(priv)
	_ = b
	ev := nip01.NewEvent(1, "")
	if err := ev.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return ev.PubKey
}
