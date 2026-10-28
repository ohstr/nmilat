package client

import (
	"context"
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nipcash"
)

type listJournal struct {
	calls []nipcash.PendingCall
	err   error
}

func (j listJournal) Unreconciled(context.Context) ([]nipcash.PendingCall, error) {
	return j.calls, j.err
}

// T11-29 (S-CASH-119): the written-ahead calls holding a secret the user would
// lose are surfaced, oldest deadline first, including one whose request_id was
// lost (it cannot be looked up, so it is no complete recovery).
func TestUnreconciled_ListsCallsHoldingSecrets(t *testing.T) {
	secret := []nipcash.PendingSecret{{Secret: "s"}}
	j := listJournal{calls: []nipcash.PendingCall{
		{RequestID: "b", Deadline: 20, Method: nipcash.MethodCashTransfer, Secrets: secret},
		{RequestID: "c", Deadline: 5, Method: nipcash.MethodCashTransfer}, // to a pubkey: nothing to lose
		{RequestID: "", Deadline: 30, Method: nipcash.MethodCashConsolidate, Secrets: secret},
		{RequestID: "a", Deadline: 10, Method: nipcash.MethodMintCash, Secrets: secret},
		{RequestID: "d", Deadline: 15, Method: nipcash.MethodCashOrder, BuyerKey: "k"},
	}}
	got, err := (&Client{}).Unreconciled(context.Background(), j)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, pc := range got {
		ids = append(ids, pc.RequestID)
	}
	if want := []string{"a", "d", "b", ""}; len(ids) != len(want) || ids[0] != "a" || ids[1] != "d" || ids[2] != "b" || ids[3] != "" {
		t.Fatalf("got %q, want %q", ids, want)
	}
	got[0].Secrets[0].Secret = "changed"
	if j.calls[3].Secrets[0].Secret == "changed" {
		t.Fatal("the caller's copy shares the journal's secrets")
	}
}

func TestUnreconciled_Errors(t *testing.T) {
	if _, err := (&Client{}).Unreconciled(context.Background(), nil); !errors.Is(err, ErrNoJournal) {
		t.Fatalf("nil journal: %v, want ErrNoJournal", err)
	}
	boom := errors.New("disk")
	if _, err := (&Client{}).Unreconciled(context.Background(), listJournal{err: boom}); !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the journal's", err)
	}
}
