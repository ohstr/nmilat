package nipcw

import (
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

// T12-14 (S-CW-102..104, 110, 135).
func TestVerifyMemberRequest(t *testing.T) {
	priv, pub := generateTestKeypair(t)
	_, hub := generateTestKeypair(t)
	_, hub2 := generateTestKeypair(t)
	wallet := testWalletPubkey
	conn := newTestConnectionKey(t).Pubkey()
	now := time.Unix(1720000000, 0)
	never := func(string) bool { return false }
	sign := func(at int64, tags ...[]string) *nip01.Event {
		t.Helper()
		ev, err := BySigning(priv).signProof(at, tags...)
		if err != nil {
			t.Fatal(err)
		}
		return ev
	}
	d, w := []string{"d", hub}, []string{"wallet", wallet}
	rot, c := []string{"action", "rotate"}, []string{"connection", conn}

	for _, at := range []int64{now.Unix() - 86400, now.Unix() + 60} {
		mr, err := VerifyMemberRequest(sign(at, d, rot, w, c), hub, now, never)
		if err != nil || mr.Pubkey != pub || mr.Action != ActionRotate || mr.Wallet != wallet || mr.Connection != conn || mr.CheckConnection() != nil {
			t.Errorf("at %d: %+v %v", at, mr, err)
		}
	}
	if mr, err := VerifyMemberRequest(sign(now.Unix(), d, []string{"action", "freeze"}, w), hub, now, never); err != nil || mr.Connection != "" || mr.CheckConnection() != nil {
		t.Errorf("freeze: %+v %v", mr, err)
	}

	bad := map[string]*nip01.Event{
		"now-86401":          sign(now.Unix()-86401, d, rot, w, c),
		"now+61":             sign(now.Unix()+61, d, rot, w, c),
		"two actions":        sign(now.Unix(), d, rot, []string{"action", "freeze"}, w, c),
		"sweep":              sign(now.Unix(), d, []string{"action", "sweep"}, w),
		"no action":          sign(now.Unix(), d, w, c),
		"connection freeze":  sign(now.Unix(), d, []string{"action", "freeze"}, w, c),
		"rotate without key": sign(now.Unix(), d, rot, w),
		"two connections":    sign(now.Unix(), d, rot, w, c, c),
		"terms tag":          sign(now.Unix(), d, rot, w, c, []string{"terms", "1:1:0:never"}),
		"d H2":               sign(now.Unix(), []string{"d", hub2}, rot, w, c),
		"no wallet":          sign(now.Unix(), d, rot, c),
	}
	tampered := sign(now.Unix(), d, rot, w, c)
	tampered.Tags[2][1] = hub2
	bad["id altered"] = tampered
	other := nip01.NewEvent(23198, "", d, rot, w, c)
	other.CreatedAt = uint64(now.Unix())
	_ = other.Sign(priv)
	bad["kind 23198"] = other
	for name, ev := range bad {
		asked := false
		if _, err := VerifyMemberRequest(ev, hub, now, func(string) bool { asked = true; return false }); codeOf(err) != ErrUnauthorized || asked {
			t.Errorf("%s: %v (consumed asked %v), want UNAUTHORIZED", name, err, asked)
		}
	}
	if _, err := VerifyMemberRequest(sign(now.Unix(), d, rot, w, c), hub, now, func(string) bool { return true }); codeOf(err) != ErrRequestReused {
		t.Errorf("consumed: %v", err)
	}
	mr, err := VerifyMemberRequest(sign(now.Unix(), d, rot, w, []string{"connection", "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}), hub, now, never)
	if err != nil || codeOf(mr.CheckConnection()) != ErrRestricted {
		t.Errorf("invalid x-only key: %v / %v, want a RESTRICTED hint", err, mr.CheckConnection())
	}
}

func TestNewMemberRequest(t *testing.T) {
	priv, _ := generateTestKeypair(t)
	_, hub := generateTestKeypair(t)
	conn := newTestConnectionKey(t).Pubkey()
	ev, err := NewMemberRequest(priv, hub, ActionRotate, testWalletPubkey, conn)
	if err != nil {
		t.Fatal(err)
	}
	if mr, err := VerifyMemberRequest(ev, hub, time.Now(), nil); err != nil || mr.Connection != conn {
		t.Fatalf("round trip: %+v %v", mr, err)
	}
	for name, f := range map[string]func() error{
		"freeze with key": func() error { _, err := NewMemberRequest(priv, hub, ActionFreeze, testWalletPubkey, conn); return err },
		"rotate no key":   func() error { _, err := NewMemberRequest(priv, hub, ActionRotate, testWalletPubkey, ""); return err },
		"sweep":           func() error { _, err := NewMemberRequest(priv, hub, "sweep", testWalletPubkey, ""); return err },
	} {
		if f() == nil {
			t.Errorf("%s: signed", name)
		}
	}
}
