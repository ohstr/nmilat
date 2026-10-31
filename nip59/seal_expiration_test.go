package nip59_test

import (
	"context"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip59"
)

// WrapSeal with WithWrapExpiration puts the expiration on the wrap only; the
// recipient still opens it, and 0 sets none.
func TestWrapSealExpiration(t *testing.T) {
	alice, bob := key(t, alicePriv), key(t, bobPriv)
	rumor := nip01.NewEvent(14, "expires", []string{"p", bob.PubKey()})
	rumor.CreatedAt = 1700000000
	seal, err := nip59.Seal(context.Background(), alice, rumor, bob.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := nip59.WrapSeal(seal, bob.PubKey(), nip59.WithWrapExpiration(1800000000))
	if err != nil {
		t.Fatal(err)
	}
	if len(wrap.Tags) != 2 || wrap.Tags[1][0] != "expiration" || wrap.Tags[1][1] != "1800000000" {
		t.Fatalf("wrap tags: %v", wrap.Tags)
	}
	if len(seal.Tags) != 0 {
		t.Fatalf("seal tags: %v", seal.Tags)
	}
	got, err := nip59.Unwrap(context.Background(), bob, wrap, nip59.OpenOptions{})
	if err != nil || got.Rumor.ID != rumor.ID {
		t.Fatalf("unwrap: %v %+v", err, got)
	}
	plain, err := nip59.WrapSeal(seal, bob.PubKey(), nip59.WithWrapExpiration(0))
	if err != nil || len(plain.Tags) != 1 {
		t.Fatalf("no expiration for 0: %v %v", err, plain.Tags)
	}
}
