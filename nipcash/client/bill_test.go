package client

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// Bill exists to make one specific mistake impossible: naming which bill an item acts
// on without supplying the secret that proves you hold it.
//
// That mistake was live and silent. The two were plain string fields, so a struct
// literal setting only Target compiled, and the failure arrived at runtime — as an
// OMISSION from the hub, which is information-free by design, so the caller could not
// learn what was wrong. On a money path that is the worst available failure shape.

func TestBillFor_TakesBothHalvesFromOneToken(t *testing.T) {
	tok := nipcash.Token{
		WalletPubkey: strings.Repeat("ab", 32),
		Secret:       strings.Repeat("cd", 32),
	}
	b, err := BillFor(tok)
	if err != nil {
		t.Fatalf("BillFor: %v", err)
	}
	if b.Target() != tok.WalletPubkey {
		t.Errorf("Target() = %q, want %q", b.Target(), tok.WalletPubkey)
	}
	if b.connSecret != tok.Secret {
		t.Error("the connection secret did not come from the token")
	}
	if !b.ok() {
		t.Error("a Bill built from a complete token reports as not ok")
	}
}

// Either half missing is refused AT CONSTRUCTION, where the caller can be told which
// bill is wrong — not deeper down, where the only available answer is silence.
func TestBillFromParts_RefusesAHalf(t *testing.T) {
	for _, tc := range []struct {
		name, pubkey, secret string
	}{
		{"no secret", strings.Repeat("ab", 32), ""},
		{"no pubkey", "", strings.Repeat("cd", 32)},
		{"neither", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := BillFromParts(tc.pubkey, tc.secret)
			if err == nil {
				t.Fatal("BillFromParts() = nil error; a half-built bill cannot be served")
			}
			if b.ok() {
				t.Error("a refused Bill reports as ok")
			}
		})
	}

	// And the error names the bill, so a caller with a batch of fifty knows which.
	pubkey := strings.Repeat("ab", 32)
	_, err := BillFromParts(pubkey, "")
	if err == nil || !strings.Contains(err.Error(), pubkey) {
		t.Errorf("error should name the offending bill, got %v", err)
	}
}

// TestBatchMethods_RejectAZeroBillByName is the guard behind the type.
//
// A zero Bill is still expressible — Go has no way to forbid `BatchRedeem{}` — so the
// send path must turn it into a named error rather than an item the hub omits. Asserted
// for every method, because each has its own builder and a guard is easy to add to
// three of four.
func TestBatchMethods_RejectAZeroBillByName(t *testing.T) {
	// A session with real announced limits, because limit validation runs BEFORE the
	// builders — without it every case fails on the limits instead, which is what the
	// first version of this test actually asserted.
	//
	// No relay is reachable, and none is needed: the builders run before anything is
	// sent, so a zero Bill fails at item construction.
	d := transport.DefaultLimits()
	s := &BatchSession{
		relays: []string{"ws://127.0.0.1:1"},
		announcement: &transport.Announcement{
			Version: 1,
			Inbox:   strings.Repeat("ab", 32),
			Limits: transport.AnnouncedLimits{
				MaxBytes:              d.MaxEnvelopeBytes,
				MaxItems:              d.MaxItems,
				MaxConsolidateSources: d.MaxConsolidateSources,
				PadBucketBytes:        d.PadBucketBytes,
				MaxVerifyBudget:       d.MaxVerifyBudget,
			},
		},
	}
	ctx := context.Background()
	cred := nipcash.BySigning(hex.EncodeToString([]byte(strings.Repeat("k", 32))))

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"StatusMany", func() error {
			_, err := s.StatusMany(ctx, []BatchStatus{{ID: "x", Credential: cred}})
			return err
		}},
		{"RedeemMany", func() error {
			_, err := s.RedeemMany(ctx, []BatchRedeem{{ID: "x", Params: nipcash.CashRedeemParams{Invoice: "lnbc1"}}})
			return err
		}},
		{"TransferMany", func() error {
			_, err := s.TransferMany(ctx, []BatchTransfer{{ID: "x"}})
			return err
		}},
		{"ConsolidateMany", func() error {
			_, err := s.ConsolidateMany(ctx, []BatchConsolidate{{ID: "x", Credential: cred}})
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatal("a zero Bill was accepted; it can only produce an item the hub omits")
			}
			if !strings.Contains(err.Error(), "no bill") {
				t.Errorf("error should say the item has no bill, got %v", err)
			}
			if !strings.Contains(err.Error(), "BillFor") {
				t.Errorf("error should name the constructor to use, got %v", err)
			}
		})
	}
}
