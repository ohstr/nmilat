package nip59

import (
	"encoding/hex"
	"errors"
	"testing"

	btcec "github.com/flokiorg/go-flokicoin/crypto"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

func newKey(t *testing.T) (priv, pub string) {
	t.Helper()
	k, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	priv = hex.EncodeToString(k.Serialize())
	pub, err = utils.GetPublicKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

// T15-01: a signed rumor is refused; the wrap is signed by the given wrap key.
func TestWrapWithKeyRefusesSignedRumorAndUsesTheKey(t *testing.T) {
	userPriv, userPub := newKey(t)
	wrapPriv, wrapPub := newKey(t)

	signed := nip01.NewEvent(9525, "")
	if err := signed.Sign(userPriv); err != nil {
		t.Fatal(err)
	}
	if _, err := WrapWithKey(signed, userPriv, userPub, wrapPriv); !errors.Is(err, ErrSignedRumor) {
		t.Fatalf("signed rumor: err = %v, want ErrSignedRumor", err)
	}

	rumor := nip01.NewEvent(9525, "", []string{"w", "ab"})
	w, err := WrapWithKey(rumor, userPriv, userPub, wrapPriv, WithWrapExpiration(1790000000))
	if err != nil {
		t.Fatal(err)
	}
	if w.PubKey != wrapPub {
		t.Fatalf("wrap pubkey %s, want the wrap key's %s", w.PubKey, wrapPub)
	}
	if err := w.Verify(); err != nil {
		t.Fatal(err)
	}
	if got := w.GetTag("expiration"); len(got) < 1 || got[0] != "1790000000" {
		t.Fatalf("expiration tag = %v", got)
	}
	if rumor.Sig != "" || rumor.ID != "" {
		t.Fatal("WrapWithKey changed the caller's rumor")
	}

	got, signer, err := UnwrapWithKey(w, userPriv)
	if err != nil {
		t.Fatal(err)
	}
	if signer != userPub || got.PubKey != userPub || got.Kind != 9525 || got.Sig != "" {
		t.Fatalf("unwrapped %+v by %s", got, signer)
	}
	id, _ := got.HashID()
	if got.ID != hex.EncodeToString(id) {
		t.Fatal("rumor id is not its hash")
	}

	// A kind 5 signed by the wrap key names the wrap: the key can delete it.
	del, err := nip01.NewSignedEvent(5, "", wrapPriv, []string{"e", w.ID})
	if err != nil {
		t.Fatal(err)
	}
	if del.PubKey != w.PubKey {
		t.Fatal("the deletion is not by the wrap's author")
	}
}

func TestWrapWithKeyRumorAuthor(t *testing.T) {
	userPriv, userPub := newKey(t)
	_, otherPub := newKey(t)
	wrapPriv, _ := newKey(t)
	r := nip01.NewUnsignedEvent(9525, otherPub, "")
	if _, err := WrapWithKey(r, userPriv, userPub, wrapPriv); !errors.Is(err, ErrRumorAuthor) {
		t.Fatalf("err = %v, want ErrRumorAuthor", err)
	}
	if _, err := WrapWithKey(nip01.NewEvent(9525, ""), userPriv, userPub, "zz"); err == nil {
		t.Fatal("a bad wrap key was accepted")
	}
}

func TestUnwrapRefusesOthersAndTampering(t *testing.T) {
	userPriv, userPub := newKey(t)
	otherPriv, otherPub := newKey(t)
	wrapPriv, _ := newKey(t)
	w, err := WrapWithKey(nip01.NewEvent(14, "hi"), userPriv, userPub, wrapPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := UnwrapWithKey(w, otherPriv); !errors.Is(err, ErrNotWrap) {
		t.Fatalf("another key opened it: %v", err)
	}
	bad := *w
	bad.Content = bad.Content[:len(bad.Content)-4] + "AAAA"
	if _, _, err := UnwrapWithKey(&bad, userPriv); !errors.Is(err, ErrNotWrap) {
		t.Fatalf("tampered wrap: %v", err)
	}
	seal := *w
	seal.Kind = KindSeal
	if _, _, err := UnwrapWithKey(&seal, userPriv); !errors.Is(err, ErrNotWrap) {
		t.Fatalf("a seal given as a wrap: %v", err)
	}
	// Wrap (throwaway key) round-trips through UnwrapWithKey too.
	payload := nip01.NewUnsignedEvent(14, otherPub, "dm")
	w2, err := Wrap(payload, otherPriv, userPub)
	if err != nil {
		t.Fatal(err)
	}
	got, signer, err := UnwrapWithKey(w2, userPriv)
	if err != nil {
		t.Fatal(err)
	}
	if signer == userPub || got.Content != "dm" {
		t.Fatalf("got %+v by %s", got, signer)
	}
}
