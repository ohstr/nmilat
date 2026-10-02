package transport

import (
	"errors"
	"fmt"
	"time"
)

var (
	// ErrEnvelopeMixedHubs means items in one envelope bind to different hubs. No
	// hub can serve such an envelope: each item's proof commits to a hub identity,
	// so the foreign ones are unservable and get omitted.
	ErrEnvelopeMixedHubs = errors.New("transport: envelope mixes items bound to different hubs")
	// ErrMethodNotServable means an item names a method this transport does not
	// carry. Sending it wastes the round trip: a hub omits it.
	ErrMethodNotServable = errors.New("transport: method is not servable over the private transport")
)

// servableMethods is the set a hub may serve over this transport
// (NIP-CASH §Which Methods a Hub Serves).
//
// Spelled as wire strings rather than importing nipcash's constants, and that is a
// layering requirement rather than a preference. An item proof is signed with a
// bill's own key, and a bill's key lives behind nipcash.Credential's unexported
// methods — so nipcash is the package that must build item proofs, which means
// nipcash has to be able to import THIS package. Importing nipcash here would make
// that a cycle. transport is the lower layer and keeps no dependency on it.
//
// The names are pinned to nipcash's own constants by a test in nipcash/client,
// which can import both without creating a cycle.
//
// mint_cash is deliberately absent. It is the hub owner's method on the hub's own
// connection, and it is the one method with no retry idempotency — a hub with
// bounded replay memory could double-mint on a caller's retry.
var servableMethods = map[string]struct{}{
	"cash_status":          {},
	"cash_redeem":          {},
	"cash_transfer":        {},
	"cash_consolidate":     {},
	"create_circle_wallet": {},
}

// IsServableMethod reports whether a method may travel over the private transport.
func IsServableMethod(method string) bool {
	_, ok := servableMethods[method]
	return ok
}

// Validate checks an envelope's internal COHERENCE — that its items actually say
// what their proofs authorize — against the hub it is addressed to.
//
// Encode already checks shape: ids, counts, hex targets, budgets, and that a proof
// is non-empty. It does not and cannot check meaning, because meaning needs the hub
// identity, which Encode is not given. So a shape-valid envelope may still be
// entirely unservable, and the four ways that happens are exactly the four a
// caller is most likely to cause:
//
//   - a proof bound to a different target, method, or params than its own item;
//   - proofs carrying a stale envelope nonce, e.g. reused after regenerating one;
//   - items bound to different hubs, or to a hub other than this one;
//   - a method the transport does not serve.
//
// **Why this matters more here than in most protocols.** Every one of those
// mistakes is answered by OMISSION, and omission is deliberately information-free
// (NIP-CASH §Responses) — it has to be, or batching would become an existence
// oracle. So a client cannot tell "my proof was malformed" from "the hub does not
// hold this bill". The response is silence by design, which makes local validation
// not a convenience but the ONLY place these errors are ever diagnosable.
//
// Callers building envelopes through this package's batch helpers do not need this:
// those construct proofs rather than accept them, so incoherence is unrepresentable.
// It is for anyone assembling an Envelope by hand, and for tests.
//
// now bounds proof freshness. Pass the same instant the envelope was built with;
// a proof already stale locally will certainly be stale at the hub.
func (e Envelope) Validate(hubXOnly string, now time.Time) error {
	if len(hubXOnly) != keyHexLen || !isLowerHex(hubXOnly) {
		return fmt.Errorf("%w: hub pubkey must be %d lowercase hex characters",
			ErrAnnouncementMalformed, keyHexLen)
	}
	if len(e.Items) == 0 {
		return ErrEnvelopeNoItems
	}

	for _, item := range e.Items {
		if !IsServableMethod(item.Method) {
			return fmt.Errorf("%w: item %q calls %q", ErrMethodNotServable, item.ID, item.Method)
		}

		// A cash-mode item has no proof to check — its secret is the authorization
		// (NIP-CASH §Bearer Items). There is genuinely nothing to validate here:
		// no binding to compare, no signature to verify. What CAN still be wrong is
		// caught above and below — the method must be servable, and Encode has
		// already required that a proofless item carry a secret at all.
		//
		// Worth being explicit that this is not a hole. A hub decides whether a bill
		// is cash-mode from its own records, never from the item, so an
		// identity-bound bill cannot dodge its proof by omitting one and looking
		// bearer: the hub simply finds no matching secret and omits the item.
		if item.IsBearer() {
			if item.HasProof() {
				return fmt.Errorf("%w: item %q carries both a cash secret and a proof; "+
					"a cash-mode item authorizes with its secret alone", ErrEnvelopeMalformed, item.ID)
			}
			continue
		}

		// Recomputed from the item's own params rather than taken on trust: the
		// whole point is to catch a hash that does not match what is being sent.
		hash, err := CanonicalParamsHash(item.Params)
		if err != nil {
			return fmt.Errorf("item %q: %w", item.ID, err)
		}

		// VerifyItemProof is the hub's own check, run locally against the binding
		// this item actually implies. Reusing it — rather than re-deriving the
		// comparisons — is what guarantees local validation and remote acceptance
		// cannot drift apart.
		if _, err := VerifyItemProof(item.Proof, ProofBinding{
			Target:     item.Target,
			HubXOnly:   hubXOnly,
			Method:     item.Method,
			ParamsHash: hash,
			Nonce:      e.Nonce,
			NotAfter:   e.NotAfter,
		}, now); err != nil {
			// ErrProofWrongHub here means either a foreign hub or a mixed envelope.
			// Reported as the mixed-hub error because that is the actionable
			// diagnosis: the caller assembled items that cannot travel together.
			if errors.Is(err, ErrProofWrongHub) {
				return fmt.Errorf("%w: item %q: %v", ErrEnvelopeMixedHubs, item.ID, err)
			}
			return fmt.Errorf("item %q: %w", item.ID, err)
		}
	}
	return nil
}
