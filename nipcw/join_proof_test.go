package nipcw

import (
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

type proofFixture struct {
	memberPriv, member, hub, hub2, conn string
	now                                 time.Time
	terms                               string
}

func newProofFixture(t *testing.T) proofFixture {
	t.Helper()
	priv, pub := generateTestKeypair(t)
	_, hub := generateTestKeypair(t)
	_, hub2 := generateTestKeypair(t)
	return proofFixture{memberPriv: priv, member: pub, hub: hub, hub2: hub2, conn: newTestConnectionKey(t).Pubkey(),
		now: time.Unix(1720000000, 0), terms: "100000:200000:0:monthly"}
}

func (f proofFixture) request(t *testing.T, ev *nip01.Event) CreateCircleWalletRequest {
	t.Helper()
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	return CreateCircleWalletRequest{Pubkey: f.member, ConnectionPubkey: f.conn, MaxAmount: 100000, MaxReceive: 200000,
		BudgetRenewal: RenewalMonthly, IdentityEvent: string(raw)}
}

func (f proofFixture) event(t *testing.T, kind int, createdAt int64, tags ...[]string) *nip01.Event {
	t.Helper()
	ev := nip01.NewEvent(kind, "", tags...)
	ev.CreatedAt = uint64(createdAt)
	if err := ev.Sign(f.memberPriv); err != nil {
		t.Fatal(err)
	}
	return ev
}

func (f proofFixture) good(t *testing.T, createdAt int64) *nip01.Event {
	return f.event(t, 23199, createdAt, []string{"d", f.hub}, []string{"connection", f.conn}, []string{"terms", f.terms})
}

func codeOf(err error) string {
	var pe *JoinProofError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// T12-03 (S-CW-04..10): checks 1–7 refuse with UNAUTHORIZED, check 8 with
// REQUEST_REUSED, and consumed is asked only after 1–7 pass.
func TestVerifyJoinProof(t *testing.T) {
	f := newProofFixture(t)
	now := f.now.Unix()
	never := func(string) bool { return false }

	ev := f.good(t, now)
	id, err := VerifyJoinProof(f.request(t, ev), f.hub, f.now, never)
	if err != nil || id != ev.ID {
		t.Fatalf("good proof: %s %v", id, err)
	}
	for _, at := range []int64{now - 300, now + 60} {
		if _, err := VerifyJoinProof(f.request(t, f.good(t, at)), f.hub, f.now, never); err != nil {
			t.Errorf("created_at %d (inclusive bound): %v", at, err)
		}
	}

	altered := f.good(t, now)
	altered.Tags[2][1] = "100001:200000:0:monthly" // id no longer matches
	broken := f.good(t, now)
	broken.Sig = broken.Sig[:len(broken.Sig)-2] + "00"
	otherPriv, _ := generateTestKeypair(t)
	other := nip01.NewEvent(23199, "", []string{"d", f.hub}, []string{"connection", f.conn}, []string{"terms", f.terms})
	other.CreatedAt = uint64(now)
	if err := other.Sign(otherPriv); err != nil {
		t.Fatal(err)
	}
	derived := mustXOnly(t, randomKeyHex(t))

	unauthorized := map[string]*nip01.Event{
		"23198 proof":       f.event(t, 23198, now, []string{"d", f.hub}, []string{"connection", f.conn}, []string{"terms", f.terms}),
		"action tag":        f.event(t, 23199, now, []string{"d", f.hub}, []string{"action", "rotate"}, []string{"connection", f.conn}, []string{"terms", f.terms}),
		"id altered":        altered,
		"broken sig":        broken,
		"signer not pubkey": other,
		"now-301":           f.good(t, now-301),
		"now+61":            f.good(t, now+61),
		"d derived key":     f.event(t, 23199, now, []string{"d", derived}, []string{"connection", f.conn}, []string{"terms", f.terms}),
		"d Hub H2":          f.event(t, 23199, now, []string{"d", f.hub2}, []string{"connection", f.conn}, []string{"terms", f.terms}),
		"d doubled":         f.event(t, 23199, now, []string{"d", f.hub}, []string{"d", f.hub}, []string{"connection", f.conn}, []string{"terms", f.terms}),
		"connection swap":   f.event(t, 23199, now, []string{"d", f.hub}, []string{"connection", newTestConnectionKey(t).Pubkey()}, []string{"terms", f.terms}),
		"connection twice":  f.event(t, 23199, now, []string{"d", f.hub}, []string{"connection", f.conn}, []string{"connection", f.conn}, []string{"terms", f.terms}),
		"no terms":          f.event(t, 23199, now, []string{"d", f.hub}, []string{"connection", f.conn}),
		"terms tampered":    f.event(t, 23199, now, []string{"d", f.hub}, []string{"connection", f.conn}, []string{"terms", "100000:200000:0:yearly"}),
		"terms Monthly":     f.event(t, 23199, now, []string{"d", f.hub}, []string{"connection", f.conn}, []string{"terms", "100000:200000:0:Monthly"}),
		"terms leading 0":   f.event(t, 23199, now, []string{"d", f.hub}, []string{"connection", f.conn}, []string{"terms", "0100000:200000:0:monthly"}),
		"terms doubled":     f.event(t, 23199, now, []string{"d", f.hub}, []string{"connection", f.conn}, []string{"terms", f.terms}, []string{"terms", f.terms}),
	}
	for name, ev := range unauthorized {
		asked := false
		_, err := VerifyJoinProof(f.request(t, ev), f.hub, f.now, func(string) bool { asked = true; return false })
		if codeOf(err) != ErrUnauthorized {
			t.Errorf("%s: %v, want UNAUTHORIZED", name, err)
		}
		if asked {
			t.Errorf("%s: consumed was asked before checks 1–7 passed", name)
		}
	}
	if _, err := VerifyJoinProof(f.request(t, f.good(t, now)), f.hub, f.now, func(string) bool { return true }); codeOf(err) != ErrRequestReused {
		t.Errorf("consumed: %v, want REQUEST_REUSED", err)
	}
}

// T12-27 for VerifyJoinProof: 2^63-1 accepted; 2^63 is BAD_REQUEST and consumed is
// never called. Other malformed params are BAD_REQUEST too.
func TestVerifyJoinProof_BadRequest(t *testing.T) {
	f := newProofFixture(t)
	maxs := strconv.FormatUint(MaxTermValue, 10)
	f.terms = maxs + ":" + maxs + ":" + maxs + ":monthly"
	req := f.request(t, f.good(t, f.now.Unix()))
	req.MaxAmount, req.MaxReceive, req.Expiry = MaxTermValue, MaxTermValue, MaxTermValue
	if _, err := VerifyJoinProof(req, f.hub, f.now, func(string) bool { return false }); err != nil {
		t.Fatalf("2^63-1: %v", err)
	}
	mutate := map[string]func(*CreateCircleWalletRequest){
		"max_amount 2^63":  func(r *CreateCircleWalletRequest) { r.MaxAmount = MaxTermValue + 1 },
		"max_receive 2^63": func(r *CreateCircleWalletRequest) { r.MaxReceive = MaxTermValue + 1 },
		"expiry 2^63":      func(r *CreateCircleWalletRequest) { r.Expiry = MaxTermValue + 1 },
		"renewal Monthly":  func(r *CreateCircleWalletRequest) { r.BudgetRenewal = "Monthly" },
		"63-char pubkey":   func(r *CreateCircleWalletRequest) { r.Pubkey = r.Pubkey[:63] },
		"uppercase pubkey": func(r *CreateCircleWalletRequest) { r.Pubkey = "AB" + r.Pubkey[2:] },
		"no connection":    func(r *CreateCircleWalletRequest) { r.ConnectionPubkey = "" },
		"off-curve conn": func(r *CreateCircleWalletRequest) {
			r.ConnectionPubkey = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		},
		"conn equals pubkey":  func(r *CreateCircleWalletRequest) { r.ConnectionPubkey = r.Pubkey },
		"identity not object": func(r *CreateCircleWalletRequest) { r.IdentityEvent = `"x"` },
	}
	for name, m := range mutate {
		r := req
		m(&r)
		asked := false
		_, err := VerifyJoinProof(r, f.hub, f.now, func(string) bool { asked = true; return false })
		if codeOf(err) != ErrBadRequest || asked {
			t.Errorf("%s: %v (consumed asked %v), want BAD_REQUEST", name, err, asked)
		}
	}
}

func TestParseCreateCircleWalletRequest(t *testing.T) {
	good := `{"pubkey":"a","connection_pubkey":"b","max_amount":1,"max_receive":2,"identity_event":"{}"}`
	if r, err := ParseCreateCircleWalletRequest([]byte(good)); err != nil || r.MaxReceive != 2 {
		t.Fatalf("good: %+v %v", r, err)
	}
	for _, s := range []string{
		`{"pubkey":"a","connection_pubkey":"b","max_amount":1,"identity_event":"{}"}`,
		`{"pubkey":"a","connection_pubkey":"b","max_amount":1.5,"max_receive":2,"identity_event":"{}"}`,
		`{"pubkey":"a","connection_pubkey":"b","max_amount":-1,"max_receive":2,"identity_event":"{}"}`,
		`{"pubkey":"a","connection_pubkey":"b","max_amount":1,"max_receive":2,"identity_event":{}}`,
		`[]`,
	} {
		if _, err := ParseCreateCircleWalletRequest([]byte(s)); codeOf(err) != ErrBadRequest {
			t.Errorf("%s: %v, want BAD_REQUEST", s, err)
		}
	}
}

// T12-28 (CW-DM-01).
func TestRetainUntil(t *testing.T) {
	if got := JoinProofRetainUntil(1720000000); got != 1720000360 {
		t.Errorf("JoinProofRetainUntil = %d", got)
	}
	if got := MemberRequestRetainUntil(1720000000); got != 1720086460 {
		t.Errorf("MemberRequestRetainUntil = %d", got)
	}
}
