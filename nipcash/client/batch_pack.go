package client

import (
	"errors"
	"fmt"
	"time"

	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// ErrItemTooLarge means one item cannot fit in any envelope the hub will accept, so
// no amount of splitting helps. Almost always a cash_consolidate with more sources
// than the hub's announced max_bytes allows.
var ErrItemTooLarge = errors.New("nipcash/client: a single item exceeds the hub's envelope limit")

// ErrTooManySources is a consolidate whose sources exceed the Hub's announced
// max_consolidate_sources, which the Hub refuses with QUOTA_EXCEEDED. It comes
// wrapped with ErrItemTooLarge: the caller splits it into several consolidates,
// each a new call.
var ErrTooManySources = errors.New("nipcash/client: a consolidate has more sources than the hub's max_consolidate_sources")

// fitsAlone checks that b's item, built on its own against a throwaway binding,
// fits an envelope the Hub accepts: an item that does not can never be sent,
// however a batch is split. A builder that cannot build is reported too.
func fitsAlone(b itemBuilder, hubXOnly string, limits transport.Limits, notAfter int64) error {
	_, _, _, err := packOne([]itemBuilder{b}, hubXOnly, limits, notAfter)
	return err
}

// itemBuilder produces one item once its envelope's binding is known.
//
// The indirection exists because of an ordering constraint that is easy to miss and
// expensive to get wrong: an item's proof commits to its envelope's NONCE, so an item
// cannot be built until it is known which envelope will carry it. Splitting a batch
// after building proofs would leave every moved item bound to a nonce it no longer
// travels under — and a hub answers that with omission, which is information-free, so
// the caller would never learn why.
//
// So packing decides the split first, over unbuilt items, and construction happens
// per envelope afterwards.
type itemBuilder struct {
	// ID is the caller's own id for this item, carried through to its outcome.
	ID string
	// Build returns the item for a given envelope binding.
	Build func(id string, b nipcash.ItemBinding) (transport.Item, error)
	// RequestID is the request_id the item carries, "" for a call without one.
	RequestID string
	// Pending returns the call to write ahead for the envelope deadline it was
	// packed under; nil for an item that writes nothing ahead.
	Pending func(deadline int64) nipcash.PendingCall
	// Measure, when set, builds a stand-in of the same size as Build's item
	// without using anything up. It is set for a single-use item (a circle
	// join, whose prepared join builds once): packing decides the fit on the
	// stand-in and calls Build only for the envelope that will carry it, so an
	// item that spills into a later envelope is still built there.
	Measure func(id string, b nipcash.ItemBinding) (transport.Item, error)
}

// packedEnvelope is one request envelope, built and ready to wrap.
type packedEnvelope struct {
	Envelope transport.Envelope
	// ItemIDs is what this envelope carries, in order, so a response can be joined
	// back to the caller's own items and a failed publish can mark exactly these
	// as unserved.
	ItemIDs []string
}

// packItems splits builders across as few envelopes as the hub's announced limits
// allow, and builds each envelope's items bound to that envelope.
//
// Fitting is tested by actually encoding, not by estimating. That is slower — an
// envelope is re-marshalled as it grows — and it is the right trade: an estimate can
// disagree with the hub, and this codebase has already been wrong once about
// consolidate sizing. Encode is the same check the hub's decoder applies, so a
// packed envelope that encodes here cannot be refused there for size.
//
// notAfterWindow is how long the envelopes stay valid. One timestamp is shared by
// every envelope in the batch so a caller's whole batch expires together.
func packItems(builders []itemBuilder, hubXOnly string, limits transport.Limits, notAfterWindow time.Duration) ([]packedEnvelope, error) {
	if len(builders) == 0 {
		return nil, nil
	}
	if err := limits.Validate(); err != nil {
		return nil, fmt.Errorf("nipcash/client: hub announced an unusable envelope policy: %w", err)
	}

	notAfter := time.Now().Add(notAfterWindow).Unix()
	var out []packedEnvelope

	remaining := builders
	for len(remaining) > 0 {
		env, ids, consumed, err := packOne(remaining, hubXOnly, limits, notAfter)
		if err != nil {
			return nil, err
		}
		out = append(out, packedEnvelope{Envelope: env, ItemIDs: ids})
		remaining = remaining[consumed:]
	}
	return out, nil
}

// packOne fills a single envelope from the front of builders, returning how many it
// consumed.
func packOne(builders []itemBuilder, hubXOnly string, limits transport.Limits, notAfter int64) (transport.Envelope, []string, int, error) {
	nonce, err := transport.NewNonce()
	if err != nil {
		return transport.Envelope{}, nil, 0, fmt.Errorf("nipcash/client: nonce: %w", err)
	}
	replyTo, err := transport.NewNonce()
	if err != nil {
		return transport.Envelope{}, nil, 0, fmt.Errorf("nipcash/client: reply tag: %w", err)
	}

	binding := nipcash.ItemBinding{HubXOnly: hubXOnly, Nonce: nonce, NotAfter: notAfter}
	env := transport.Envelope{
		Version:  transport.EnvelopeVersion,
		NotAfter: notAfter,
		Nonce:    nonce,
		ReplyTo:  replyTo,
	}

	var ids []string
	consumed := 0
	for _, b := range builders {
		probe := b.Build
		if b.Measure != nil {
			probe = b.Measure
		}
		item, err := probe(b.ID, binding)
		if err != nil {
			// A builder that cannot produce an item at all — a captured-proof
			// credential, a malformed invoice — is the caller's error and must
			// surface, not be silently dropped into an unserved outcome.
			return transport.Envelope{}, nil, 0, fmt.Errorf("item %q: %w", b.ID, err)
		}

		candidate := env
		candidate.Items = append(append([]transport.Item(nil), env.Items...), item)
		if _, err := candidate.Encode(limits); err != nil {
			if consumed == 0 {
				// It did not fit in an EMPTY envelope, so no split helps.
				return transport.Envelope{}, nil, 0, fmt.Errorf("%w: item %q: %v", ErrItemTooLarge, b.ID, err)
			}
			// Full. Leave this item for the next envelope, where it will be rebuilt
			// against that envelope's own nonce — which is exactly why builders are
			// deferred rather than items pre-built.
			break
		}
		if b.Measure != nil {
			// The fit was decided on the stand-in; the real item is built once,
			// here, for the envelope that carries it.
			built, err := b.Build(b.ID, binding)
			if err != nil {
				return transport.Envelope{}, nil, 0, fmt.Errorf("item %q: %w", b.ID, err)
			}
			candidate.Items[len(candidate.Items)-1] = built
			if _, err := candidate.Encode(limits); err != nil {
				return transport.Envelope{}, nil, 0, fmt.Errorf("item %q: built larger than measured: %w", b.ID, err)
			}
		}
		env = candidate
		ids = append(ids, b.ID)
		consumed++
	}

	if consumed == 0 {
		return transport.Envelope{}, nil, 0, fmt.Errorf("nipcash/client: packed no items and reported no reason")
	}
	return env, ids, consumed, nil
}
