package cashtest

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	btcec "github.com/flokiorg/go-flokicoin/crypto"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/nip59"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcash/transport"
	"github.com/ohstr/nmilat/utils"
)

// DefaultTombstoneWindow is the fake Hub's tombstone retention window, the
// 15 days NIP-CASH §Answering About a Destroyed Bill calls reasonable.
const DefaultTombstoneWindow = 15 * 24 * time.Hour

// FakeHub serves NIP-CASH's private transport and its Cash Hub connection on a
// set of in-process relays.
//
// Envelopes are served in the spec's order E1 to E6 (NIP-CASH §Serving an
// Envelope). What each item gets is up to Decide: the fake keeps no ledger, so a
// test states which targets it holds and how each is answered. Every result is
// stamped with result_type = the item's method unless Decide set one, and every
// reply chunk is signed by a fresh key with a randomised created_at and only a p
// tag (§The Reply Key).
type FakeHub struct {
	Clock  Clock
	Relays []*Relay
	// NodePriv is the node identity: it signs the announcement. InboxPriv
	// decrypts requests.
	NodePriv, InboxPriv string
	Limits              transport.Limits
	TombstoneWindow     time.Duration
	// Fault, when set, picks the fault for each item.
	Fault      func(ItemCtx) Fault
	TrustedIAs map[string]bool

	// Decide answers one item; nil omits it. Unset, every item is omitted, as for
	// a Hub that holds none of the targets.
	Decide func(ItemCtx) *transport.Result
	// ChunkSize, when > 0, splits a reply into chunks of that many results.
	ChunkSize int
	// DropChunk, when > 0, is a seq the Hub never publishes.
	DropChunk int

	t                     testing.TB
	nodeXOnly, inboxXOnly string
	walletPriv            string
	walletXOnly           string
	connSecret            string

	nonces    nonceBook
	mu        sync.Mutex
	envelopes []transport.Envelope
	committed []ItemCtx
	members   map[string]bool
	closed    chan struct{}
}

// Option configures a FakeHub.
type Option func(*FakeHub)

// WithClock sets the Hub's clock (default: a ManualClock at the current time).
func WithClock(c Clock) Option { return func(h *FakeHub) { h.Clock = c } }

// WithRelays serves on rs instead of two fresh relays.
func WithRelays(rs ...*Relay) Option { return func(h *FakeHub) { h.Relays = rs } }

// WithLimits announces l instead of transport.DefaultLimits.
func WithLimits(l transport.Limits) Option { return func(h *FakeHub) { h.Limits = l } }

// WithDecide sets the per-item decision.
func WithDecide(f func(ItemCtx) *transport.Result) Option { return func(h *FakeHub) { h.Decide = f } }

// WithFault sets the per-item fault.
func WithFault(f func(ItemCtx) Fault) Option { return func(h *FakeHub) { h.Fault = f } }

// WithKeys fixes the node and inbox keys instead of generating them.
func WithKeys(nodePriv, inboxPriv string) Option {
	return func(h *FakeHub) { h.NodePriv, h.InboxPriv = nodePriv, inboxPriv }
}

// WithChunks splits replies into chunks of size results, never publishing seq drop
// (0: none).
func WithChunks(size, drop int) Option {
	return func(h *FakeHub) { h.ChunkSize, h.DropChunk = size, drop }
}

// NewFakeHub starts a Hub, publishes its announcement on its relays and serves
// every kind-23190 and kind-23194 event they accept, until the test ends.
func NewFakeHub(t testing.TB, opts ...Option) *FakeHub {
	t.Helper()
	h := &FakeHub{
		t:               t,
		Limits:          transport.DefaultLimits(),
		TombstoneWindow: DefaultTombstoneWindow,
		TrustedIAs:      map[string]bool{},
		members:         map[string]bool{},
		closed:          make(chan struct{}),
	}
	for _, o := range opts {
		o(h)
	}
	if h.Clock == nil {
		h.Clock = NewManualClock(time.Now())
	}
	if len(h.Relays) == 0 {
		h.Relays = []*Relay{NewRelay(t), NewRelay(t)}
	}
	if h.NodePriv == "" {
		h.NodePriv, _ = Keypair(t)
	}
	if h.InboxPriv == "" {
		h.InboxPriv, _ = Keypair(t)
	}
	h.nodeXOnly = mustXOnly(t, h.NodePriv)
	h.inboxXOnly = mustXOnly(t, h.InboxPriv)
	h.walletPriv, h.walletXOnly = Keypair(t)
	h.connSecret, _ = Keypair(t)
	t.Cleanup(func() { close(h.closed) })

	ann := h.Announcement()
	for _, r := range h.Relays {
		if ok, msg := r.Publish(ann); !ok {
			t.Fatalf("cashtest: relay refused the announcement: %s", msg)
		}
		r.OnEvent(h.onEvent)
	}
	return h
}

// Keypair returns a fresh private key and its x-only public key, both hex.
func Keypair(t testing.TB) (privHex, xonlyHex string) {
	t.Helper()
	priv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	privHex = hex.EncodeToString(priv.Serialize())
	return privHex, mustXOnly(t, privHex)
}

func mustXOnly(t testing.TB, privHex string) string {
	t.Helper()
	pub, err := utils.GetPublicKey(privHex)
	if err != nil {
		t.Fatalf("cashtest: %v", err)
	}
	return pub
}

// NodeXOnly is the node identity: the announcement's author.
func (h *FakeHub) NodeXOnly() string { return h.nodeXOnly }

// InboxXOnly is the announced inbox key.
func (h *FakeHub) InboxXOnly() string { return h.inboxXOnly }

// RelayURLs lists the Hub's relays in order.
func (h *FakeHub) RelayURLs() []string {
	out := make([]string, len(h.Relays))
	for i, r := range h.Relays {
		out[i] = r.URL()
	}
	return out
}

// Announcement builds and signs the Hub's kind-11190 announcement.
func (h *FakeHub) Announcement() *nip01.Event {
	ev, err := transport.NewAnnouncement(h.nodeXOnly, h.inboxXOnly, h.Limits, h.RelayURLs())
	if err != nil {
		h.t.Fatalf("cashtest: announcement: %v", err)
	}
	if err := ev.Sign(h.NodePriv); err != nil {
		h.t.Fatalf("cashtest: sign announcement: %v", err)
	}
	return ev
}

// FakeChain is the chain the fake's connection strings name (TLV 6).
const FakeChain = "bitcoin"

// CashHubConnection is the Hub's cashhub1 string, signed by its node identity
// through nipcash.SignCashHubConnection.
func (h *FakeHub) CashHubConnection() string {
	sign, err := nipcash.LocalChainSigner(h.NodePriv, FakeChain)
	if err != nil {
		h.t.Fatalf("cashtest: signer: %v", err)
	}
	c, err := nipcash.SignCashHubConnection(nipcash.CashHubConnection{
		Pubkey: h.walletXOnly, Secret: h.connSecret, Relays: h.RelayURLs(),
		HubIdentity: h.nodeXOnly, Chain: FakeChain,
	}, sign, h.nodeXOnly)
	if err != nil {
		h.t.Fatalf("cashtest: sign cash hub connection: %v", err)
	}
	s, err := nipcash.EncodeCashHubConnection(c)
	if err != nil {
		h.t.Fatalf("cashtest: cash hub connection: %v", err)
	}
	return s
}

// CircleHubConnection is "": the fake has no Circle Wallet Hub yet, and the
// conformance cases that need one skip on an empty string.
func (h *FakeHub) CircleHubConnection() string { return "" }

// TrustIA marks an IA trusted or untrusted for later decisions.
func (h *FakeHub) TrustIA(_ testing.TB, iaXOnly string, trusted bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.TrustedIAs[iaXOnly] = trusted
}

// AddMember adds or removes a circle member.
func (h *FakeHub) AddMember(_ testing.TB, pubkey string, member bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.members[pubkey] = member
}

// Envelopes returns every envelope that passed E6, in arrival order.
func (h *FakeHub) Envelopes() []transport.Envelope {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]transport.Envelope(nil), h.envelopes...)
}

// Committed returns every item the Hub decided, in order.
func (h *FakeHub) Committed() []ItemCtx {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]ItemCtx(nil), h.committed...)
}

func (h *FakeHub) onEvent(r *Relay, ev *nip01.Event) {
	switch ev.Kind {
	case transport.KindPrivateRequest:
		h.publish(r, h.Serve(ev))
	case kindNWCRequest:
		h.serveNWC(r, ev)
	}
}

// publish puts each chunk on the arrival relay, or on the others when the
// arrival relay refuses it (NIP-CASH §Addressing the Response).
func (h *FakeHub) publish(arrival *Relay, chunks []*nip01.Event) {
	for _, ev := range chunks {
		if ok, _ := arrival.Publish(ev); ok {
			continue
		}
		for _, other := range h.Relays {
			if other != arrival {
				other.Publish(ev)
			}
		}
	}
}

// Serve answers one kind-23190 event and returns the reply chunks to publish;
// nil means no reply.
func (h *FakeHub) Serve(ev *nip01.Event) []*nip01.Event {
	conversationKey, err := transport.ConversationKeyFor(ev.PubKey, h.InboxPriv)
	if err != nil {
		return nil
	}
	plaintext, err := nip44.Decrypt(ev.Content, conversationKey[:])
	if err != nil {
		return nil // E1
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal([]byte(plaintext), &raw) != nil {
		return nil // E1
	}
	var replyTo, nonce string
	_ = json.Unmarshal(raw["reply_to"], &replyTo)
	if !isLowerHex64(replyTo) {
		return nil // E1
	}
	replyKey, err := transport.DeriveReplyKey(conversationKey, replyTo)
	if err != nil {
		return nil
	}
	now := h.Clock.Now()
	var notAfter int64
	notAfterOK := json.Unmarshal(raw["not_after"], &notAfter) == nil && raw["not_after"] != nil
	if notAfterOK && now.Unix() > notAfter {
		return nil // E2
	}
	_ = json.Unmarshal(raw["nonce"], &nonce)
	reply := func(r transport.ResponseEnvelope) []*nip01.Event {
		r.Version, r.ReqNonce = transport.EnvelopeVersion, nonce
		return h.chunks(replyKey, replyTo, r)
	}
	envError := func(code, msg string) []*nip01.Event {
		return reply(transport.ResponseEnvelope{Error: &transport.ResultError{Code: code, Message: msg}})
	}

	// E3 before E4, without claiming: an envelope refused at E4 leaves its nonce
	// unserved.
	if h.nonces.seen(nonce, now) {
		return nil
	}
	// E4.
	var items []json.RawMessage
	switch {
	case !isLowerHex64(nonce):
		return envError("BAD_REQUEST", "nonce must be 64 lowercase hex characters")
	case !notAfterOK:
		return envError("BAD_REQUEST", "not_after must be an integer")
	case time.Unix(notAfter, 0).Sub(now) > transport.MaxNotAfterWindow:
		return envError("BAD_REQUEST", "not_after is too far ahead")
	case json.Unmarshal(raw["items"], &items) != nil || len(items) == 0:
		return envError("BAD_REQUEST", "items must be a non-empty array")
	case duplicateIDs(items):
		return envError("BAD_REQUEST", "two items share an id")
	}
	if !h.nonces.claim(nonce, time.Unix(notAfter, 0), now) {
		return nil
	}
	// E5.
	if len(plaintext) > h.Limits.MaxEnvelopeBytes || len(items) > h.Limits.MaxItems {
		return envError("QUOTA_EXCEEDED", "envelope over max_bytes or max_items")
	}
	// E6, and I1 for the items Decode drops.
	env, err := transport.Decode([]byte(plaintext), h.Limits)
	switch {
	case errors.Is(err, transport.ErrVerifyBudgetExceeded), errors.Is(err, transport.ErrTooManyItems),
		errors.Is(err, transport.ErrEnvelopeTooLarge):
		return envError("QUOTA_EXCEEDED", "over the verification budget")
	case err != nil:
		return reply(transport.ResponseEnvelope{Results: []transport.Result{}}) // every item omitted
	}
	h.mu.Lock()
	h.envelopes = append(h.envelopes, *env)
	h.mu.Unlock()

	results := []transport.Result{}
	dropReply := false
	for i, item := range env.Items {
		ctx := ItemCtx{Item: item, Envelope: env, Index: i, Now: now}
		if h.Fault != nil {
			ctx.Fault = h.Fault(ctx)
		}
		switch ctx.Fault.kind {
		case faultDropBeforeCommit:
			h.nonces.release(nonce)
			return nil
		case faultCommitThenDropReply:
			dropReply = true
		case faultStallUntil:
			if !h.waitFor(ctx.Fault.until) {
				return nil
			}
			ctx.Now = h.Clock.Now()
			if ctx.Now.Unix() > env.NotAfter {
				return nil // a commit past not_after is never answered
			}
		case faultInternal, faultBreakSigner:
			results = append(results, transport.Result{ID: item.ID,
				Error: &transport.ResultError{Code: "INTERNAL", Message: "internal error"}})
			continue
		}
		if h.Decide == nil {
			continue
		}
		r := h.Decide(ctx)
		h.mu.Lock()
		h.committed = append(h.committed, ctx)
		h.mu.Unlock()
		if r == nil {
			continue
		}
		r.ID = item.ID
		if r.Error == nil && r.ResultType == "" {
			r.ResultType = item.Method
		}
		results = append(results, *r)
	}
	if dropReply {
		return nil
	}
	return reply(transport.ResponseEnvelope{Results: results})
}

// waitFor blocks until the clock reaches t, or the test ends.
func (h *FakeHub) waitFor(t time.Time) bool {
	for h.Clock.Now().Before(t) {
		select {
		case <-h.closed:
			return false
		case <-time.After(2 * time.Millisecond):
		}
	}
	return true
}

// chunks splits a reply per ChunkSize and seals each chunk.
func (h *FakeHub) chunks(replyKey [32]byte, replyTo string, r transport.ResponseEnvelope) []*nip01.Event {
	parts := [][]transport.Result{r.Results}
	if h.ChunkSize > 0 && len(r.Results) > h.ChunkSize {
		parts = nil
		for i := 0; i < len(r.Results); i += h.ChunkSize {
			parts = append(parts, r.Results[i:min(i+h.ChunkSize, len(r.Results))])
		}
	}
	var out []*nip01.Event
	for i, results := range parts {
		seq := i + 1
		if seq == h.DropChunk {
			continue
		}
		part := r
		part.Results, part.Seq, part.Total = results, seq, len(parts)
		encoded, err := part.EncodeResponse(h.Limits)
		if err != nil {
			h.t.Errorf("cashtest: encode reply chunk %d: %v", seq, err)
			return nil
		}
		sealed, err := nip44.Encrypt(string(encoded), replyKey[:])
		if err != nil {
			h.t.Errorf("cashtest: encrypt reply chunk %d: %v", seq, err)
			return nil
		}
		ev := nip01.NewEvent(transport.KindPrivateResponse, sealed)
		ev.Tags = [][]string{{"p", replyTo}}
		ev.CreatedAt = nip59.RandomizedCreatedAt()
		fresh, _ := Keypair(h.t)
		if err := ev.Sign(fresh); err != nil {
			h.t.Errorf("cashtest: sign reply chunk %d: %v", seq, err)
			return nil
		}
		out = append(out, ev)
	}
	return out
}

func isLowerHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func duplicateIDs(items []json.RawMessage) bool {
	seen := map[string]bool{}
	for _, raw := range items {
		var it struct {
			ID *string `json:"id"`
		}
		if json.Unmarshal(raw, &it) != nil || it.ID == nil {
			continue
		}
		if seen[*it.ID] {
			return true
		}
		seen[*it.ID] = true
	}
	return false
}
