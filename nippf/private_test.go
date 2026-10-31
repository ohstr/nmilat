package nippf

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip46"
	"github.com/ohstr/nmilat/nip59"
)

func localKey(t *testing.T, priv string) *nip46.LocalKey {
	t.Helper()
	k, err := nip46.NewLocalKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// A private form: one rumor wrapped to each p and to the author, every copy
// with the same id; a response wrapped back; the result to every p.
func TestPrivateDelivery(t *testing.T) {
	ctx := context.Background()
	author, op1, op2, obs := localKey(t, authorPriv), localKey(t, op1Priv), localKey(t, op2Priv), localKey(t, observerPriv)
	draft := baseForm(t, true)
	draft.ID, draft.Author, draft.ResultsAll = "", "", false
	formEv, err := draft.Event(author.PubKey(), 1000)
	if err != nil {
		t.Fatal(err)
	}
	wraps, err := Wrap(ctx, author, formEv, draft.FormRecipients())
	if err != nil {
		t.Fatal(err)
	}
	want := []string{op1.PubKey(), op2.PubKey(), obs.PubKey(), author.PubKey()}
	var tos []string
	for _, w := range wraps {
		tos = append(tos, w.To)
		if w.Wrap.Kind != nip59.KindGiftWrap || !slices.ContainsFunc(w.Wrap.Tags, func(t []string) bool { return t[0] == "expiration" && t[1] == "3000" }) {
			t.Fatalf("wrap: %v", w.Wrap.Tags)
		}
	}
	if !slices.Equal(tos, want) {
		t.Fatalf("wrapped to %v, want %v", tos, want)
	}
	var forms []*Form
	for i, k := range []*nip46.LocalKey{op1, op2, obs, author} {
		rumor, err := Open(ctx, k, wraps[i].Wrap)
		if err != nil {
			t.Fatal(err)
		}
		f, err := ParseForm(rumor, true)
		if err != nil {
			t.Fatal(err)
		}
		if f.ID != formEv.ID || f.Author != author.PubKey() {
			t.Fatalf("copy %d: id %s author %s", i, f.ID, f.Author)
		}
		forms = append(forms, f)
	}
	if _, err := Open(ctx, op2, wraps[0].Wrap); err == nil {
		t.Fatal("a wrap opens only for its recipient")
	}

	// op1 responds: wrapped to the author (and itself); e names the rumor id.
	f := forms[0]
	respEv, err := f.NewResponse(op1.PubKey(), 1100, []Choice{{Option: "yes"}, {Option: "sat"}}, []Answer{{Question: 3, Value: "2"}})
	if err != nil {
		t.Fatal(err)
	}
	if f.ResponseRecipients()[0] != author.PubKey() || len(f.ResponseRecipients()) != 1 {
		t.Fatalf("response recipients: %v", f.ResponseRecipients())
	}
	rw, err := Wrap(ctx, op1, respEv, f.ResponseRecipients())
	if err != nil || len(rw) != 2 || rw[1].To != op1.PubKey() {
		t.Fatalf("response wraps: %v %v", err, rw)
	}
	got, err := Open(ctx, author, rw[0].Wrap)
	if err != nil {
		t.Fatal(err)
	}
	r, err := ParseResponse(got)
	if err != nil || r.Form != formEv.ID || f.Check(r) != nil || r.Author != op1.PubKey() {
		t.Fatalf("response: %v %+v", err, r)
	}
	// With results "all", a response goes to every p too.
	all := *f
	all.ResultsAll = true
	if !slices.Equal(all.ResponseRecipients(), []string{author.PubKey(), op1.PubKey(), op2.PubKey(), obs.PubKey()}) {
		t.Fatalf("results all: %v", all.ResponseRecipients())
	}
	// The result goes to every p.
	resEv, err := forms[3].NewResult(1200, StatusDecided, "", r.Choices, r.Answers)
	if err != nil {
		t.Fatal(err)
	}
	resWraps, err := Wrap(ctx, author, resEv, forms[3].ResultRecipients())
	if err != nil || len(resWraps) != 4 {
		t.Fatalf("result wraps: %v %d", err, len(resWraps))
	}
}

// A wrapped event counts only when the rumor's pubkey is the seal's signer.
func TestPrivateRumorAuthor(t *testing.T) {
	ctx := context.Background()
	author, op1 := localKey(t, authorPriv), localKey(t, op1Priv)
	rumor := nip01.NewUnsignedEvent(KindResponse, author.PubKey(), "", []string{"e", id('f')})
	if _, err := Wrap(ctx, op1, rumor, []string{author.PubKey()}); !errors.Is(err, nip59.ErrRumorAuthor) {
		t.Fatalf("a rumor by another pubkey: %v", err)
	}
	signed := nip01.NewEvent(KindResponse, "", []string{"e", id('f')})
	if err := signed.Sign(op1Priv); err != nil {
		t.Fatal(err)
	}
	if _, err := Wrap(ctx, op1, signed, []string{author.PubKey()}); !errors.Is(err, nip59.ErrSignedRumor) {
		t.Fatalf("a signed rumor: %v", err)
	}
	// A seal whose rumor claims another author is refused on open.
	forged := nip01.NewUnsignedEvent(KindResponse, author.PubKey(), "", []string{"e", id('f')})
	forged.CreatedAt = 1
	_ = nip59.PrepareRumor(forged, author.PubKey())
	seal, err := forgeSeal(ctx, op1, forged, author.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	w, err := nip59.WrapSeal(seal, author.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(ctx, author, w); err == nil {
		t.Fatal("a rumor whose pubkey isn't the seal's signer counts")
	}
	if _, err := Open(ctx, author, forged); err == nil {
		t.Fatal("not a gift wrap")
	}
}

// forgeSeal seals a rumor that claims another author, signed by sender: what
// nip59.Seal never makes.
func forgeSeal(ctx context.Context, sender *nip46.LocalKey, rumor *nip01.Event, to string) (*nip01.Event, error) {
	raw := `{"id":"` + rumor.ID + `","pubkey":"` + rumor.PubKey + `","created_at":1,"kind":1019,"tags":[["e","` + id('f') + `"]],"content":""}`
	ct, err := sender.Encrypt(ctx, nip59.EncryptionNIP44V2, to, raw)
	if err != nil {
		return nil, err
	}
	seal := nip01.NewEvent(nip59.KindSeal, ct)
	seal.Tags = [][]string{}
	seal.CreatedAt = 1
	return seal, sender.Sign(ctx, seal)
}
