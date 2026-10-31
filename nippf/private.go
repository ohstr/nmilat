package nippf

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip40"
	"github.com/ohstr/nmilat/nip59"
)

// Wrapped is one gift wrap of a rumor and the pubkey it is for.
type Wrapped struct {
	To   string       `json:"to"`
	Wrap *nip01.Event `json:"wrap"`
}

// FormRecipients: who a private form is wrapped to — every p pubkey (Wrap
// adds the sender).
func (f *Form) FormRecipients() []string { return f.Recipients() }

// ResponseRecipients: who a response to a private form is wrapped to — the
// form's author, and every p pubkey if its results tag is "all".
func (f *Form) ResponseRecipients() []string {
	out := []string{f.Author}
	if f.ResultsAll {
		for _, p := range f.Recipients() {
			if !slices.Contains(out, p) {
				out = append(out, p)
			}
		}
	}
	return out
}

// ResultRecipients: who a private form's result is wrapped to — every p
// pubkey of the form.
func (f *Form) ResultRecipients() []string { return f.Recipients() }

// Wrap seals rumor once by sender and gift-wraps it to each pubkey of to and
// to the sender itself (once each), so every copy shares the rumor's id: the
// id that e tags name. The rumor must be unsigned; its pubkey is set to the
// sender's (another one is refused) and its id computed, in place. A rumor
// with an expiration tag gets it on each wrap too.
func Wrap(ctx context.Context, sender nip59.Sealer, rumor *nip01.Event, to []string) ([]Wrapped, error) {
	if rumor == nil {
		return nil, errors.New("nippf: no rumor")
	}
	if rumor.Sig != "" {
		return nil, nip59.ErrSignedRumor
	}
	self := strings.ToLower(sender.PubKey())
	if rumor.PubKey != "" && !strings.EqualFold(rumor.PubKey, self) {
		return nil, nip59.ErrRumorAuthor
	}
	if err := nip59.PrepareRumor(rumor, self); err != nil {
		return nil, err
	}
	exp, _ := nip40.GetExpiration(rumor.Tags)
	var recipients []string
	for _, p := range append(slices.Clone(to), self) {
		p = strings.ToLower(p)
		if !slices.Contains(recipients, p) {
			recipients = append(recipients, p)
		}
	}
	id := rumor.ID
	out := make([]Wrapped, 0, len(recipients))
	for _, p := range recipients {
		seal, err := nip59.Seal(ctx, sender, rumor, p)
		if err != nil {
			return nil, err
		}
		if rumor.ID != id {
			return nil, errors.New("nippf: the rumor changed while it was sealed")
		}
		w, err := nip59.WrapSeal(seal, p, nip59.WithWrapExpiration(int64(exp)))
		if err != nil {
			return nil, err
		}
		out = append(out, Wrapped{To: p, Wrap: w})
	}
	return out, nil
}

// Open unwraps a gift wrap addressed to recipient and returns its rumor, with
// its id set: a wrapped event counts only when the rumor's pubkey is the
// seal's signer, which nip59.Unwrap checks along with both signatures and the
// rumor's id. A rumor with a signature is refused (a rumor is never signed).
func Open(ctx context.Context, recipient nip59.Opener, wrap *nip01.Event) (*nip01.Event, error) {
	if wrap == nil || wrap.Kind != nip59.KindGiftWrap {
		return nil, fmt.Errorf("nippf: not a gift wrap")
	}
	o, err := nip59.Unwrap(ctx, recipient, wrap, nip59.OpenOptions{})
	if err != nil {
		return nil, err
	}
	r := o.Rumor
	if r.Sig != "" {
		return nil, nip59.ErrSignedRumor
	}
	if !strings.EqualFold(r.PubKey, o.Sender) {
		return nil, nip59.ErrRumorAuthor
	}
	if r.ID == "" {
		id, err := r.HashID()
		if err != nil {
			return nil, fmt.Errorf("nippf: rumor id: %w", err)
		}
		r.ID = hex.EncodeToString(id)
	}
	return r, nil
}
