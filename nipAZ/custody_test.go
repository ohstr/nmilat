package nipAZ_test

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip57/nip57test"
	"github.com/ohstr/nmilat/nipAZ"
	"github.com/ohstr/nmilat/nipIC"
)

var testNow = time.Now()

func trustBoth(ia string) bool { return ia == ia1.Pub || ia == ia2.Pub }

// fakeSource is a relay set the test controls: each IA's current 35522 per
// key is the latest one published.
type fakeSource struct {
	events  map[string]*nip01.Event
	current map[string]string // ia+key → id
	deleted map[string]bool
}

func newSource() *fakeSource {
	return &fakeSource{events: map[string]*nip01.Event{}, current: map[string]string{}, deleted: map[string]bool{}}
}

func (s *fakeSource) publish(ev *nip01.Event) {
	s.events[ev.ID] = ev
	for _, tag := range ev.Tags {
		if ev.Kind == nipIC.KindAttestation && tag[0] == "d" {
			s.current[ev.PubKey+tag[1]] = ev.ID
		}
	}
}

func (s *fakeSource) Fetch(_ context.Context, ref nipIC.AttestationRef) (*nip01.Event, error) {
	return s.events[ref.EventID], nil
}

func (s *fakeSource) Current(_ context.Context, ia string, key nipIC.ConnectionKey) (string, error) {
	return s.current[ia+string(key)], nil
}

func (s *fakeSource) DeletedByAuthor(_ context.Context, _ string, id string) (bool, error) {
	return s.deleted[id], nil
}

// attest has ia attest user for the github account githubUserID, dated
// createdAt (0 = now) and, with expiresAt set, expiring then.
func attest(t *testing.T, src *fakeSource, ia, user nip57test.Key, createdAt int64, expiresAt int64) *nipIC.Attestation {
	t.Helper()
	ev, err := nipIC.NewAttestation(nipIC.AttestationParams{
		PrivateKey: ia.Priv, UserPubkey: user.Pub, Platform: "github", AuthType: "oauth",
		Evidence: nipIC.Evidence{UserID: githubUserID, Username: "alice"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if createdAt != 0 || expiresAt != 0 {
		if createdAt != 0 {
			ev.CreatedAt = uint64(createdAt)
		}
		for _, tag := range ev.Tags {
			if tag[0] == nipIC.TagExpiration && expiresAt != 0 {
				tag[1] = strconv.FormatInt(expiresAt, 10)
			}
		}
		if err := ev.Sign(ia.Priv); err != nil {
			t.Fatal(err)
		}
	}
	src.publish(ev)
	att, err := nipIC.ParseAttestation(ev)
	if err != nil {
		t.Fatal(err)
	}
	return att
}

func claimFor(t *testing.T, user nip57test.Key, atts ...*nipIC.Attestation) *nip01.Event {
	t.Helper()
	var links []nipIC.AttestationLink
	for _, a := range atts {
		links = append(links, nipIC.AttestationLink{Attestation: a, Relay: "wss://ia.example.com"})
	}
	ev, err := nipIC.NewIdentityConnection(user.Priv, links, nipIC.Profile{DisplayName: "someone"})
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// attestedAlice: IA1 attests Alice for the github key, IA2 (also trusted)
// attests Mallory for the same key, later; both published 35521s.
func attestedAlice(t *testing.T) (*fakeSource, []*nip01.Event) {
	t.Helper()
	src := newSource()
	a := attest(t, src, ia1, aliceKey, testNow.Unix()-200, 0)
	m := attest(t, src, ia2, malloryKy, testNow.Unix()-100, 0)
	return src, []*nip01.Event{claimFor(t, aliceKey, a), claimFor(t, malloryKy, m)}
}

var githubID = nipAZ.ResolvedConnection(nipAZ.ConnectionKey(githubCK), "github")

// T13-16: custody is released only through the IA the request named.
func TestT13_16_SweepAllowed(t *testing.T) {
	ctx := context.Background()
	held := nipAZ.HeldValue{Key: githubID, IA: ia1.Pub}

	src, claims := attestedAlice(t)
	if err := nipAZ.SweepAllowed(ctx, held, aliceKey.Pub, claims, src, trustBoth, testNow); err != nil {
		t.Fatalf("IA1's current attestation names Alice: %v", err)
	}
	if err := nipAZ.SweepAllowed(ctx, held, malloryKy.Pub, claims, src, trustBoth, testNow); !errors.Is(err, nipAZ.ErrSweepRefused) {
		t.Errorf("Mallory through IA2: %v", err)
	}

	// IA1's attestation expired.
	src = newSource()
	a := attest(t, src, ia1, aliceKey, testNow.Unix()-200, testNow.Unix()-1)
	if err := nipAZ.SweepAllowed(ctx, held, aliceKey.Pub, []*nip01.Event{claimFor(t, aliceKey, a)}, src, trustBoth, testNow); !errors.Is(err, nipAZ.ErrSweepRefused) {
		t.Errorf("expired: %v", err)
	}
	// Deleted by IA1.
	src = newSource()
	a = attest(t, src, ia1, aliceKey, 0, 0)
	src.deleted[a.ID] = true
	if err := nipAZ.SweepAllowed(ctx, held, aliceKey.Pub, []*nip01.Event{claimFor(t, aliceKey, a)}, src, trustBoth, testNow); !errors.Is(err, nipAZ.ErrSweepRefused) {
		t.Errorf("deleted: %v", err)
	}
	// Superseded by a later IA1 attestation naming Mallory.
	src = newSource()
	a = attest(t, src, ia1, aliceKey, testNow.Unix()-200, 0)
	m := attest(t, src, ia1, malloryKy, testNow.Unix()-100, 0)
	claims = []*nip01.Event{claimFor(t, aliceKey, a), claimFor(t, malloryKy, m)}
	if err := nipAZ.SweepAllowed(ctx, held, aliceKey.Pub, claims, src, trustBoth, testNow); !errors.Is(err, nipAZ.ErrSweepRefused) {
		t.Errorf("superseded: %v", err)
	}
	if err := nipAZ.SweepAllowed(ctx, held, malloryKy.Pub, claims, src, trustBoth, testNow); err != nil {
		t.Errorf("IA1's current attestation now names Mallory: %v", err)
	}

	// Held without ia: any trusted IA's current attestation, the latest wins.
	src, claims = attestedAlice(t)
	noIA := nipAZ.HeldValue{Key: githubID}
	if err := nipAZ.SweepAllowed(ctx, noIA, malloryKy.Pub, claims, src, trustBoth, testNow); err != nil {
		t.Errorf("no ia, latest trusted (IA2): %v", err)
	}
	if err := nipAZ.SweepAllowed(ctx, noIA, aliceKey.Pub, claims, src, trustBoth, testNow); !errors.Is(err, nipAZ.ErrSweepRefused) {
		t.Errorf("no ia, older attestation: %v", err)
	}
	// An untrusted IA releases nothing.
	if err := nipAZ.SweepAllowed(ctx, noIA, malloryKy.Pub, claims, src, func(ia string) bool { return ia == ia3.Pub }, testNow); !errors.Is(err, nipAZ.ErrSweepRefused) {
		t.Errorf("untrusted: %v", err)
	}

	// A pubkey p needs no attestation; the claimant must be that pubkey.
	pk := nipAZ.HeldValue{Key: nipAZ.Pubkey(aliceKey.Pub)}
	if err := nipAZ.SweepAllowed(ctx, pk, aliceKey.Pub, nil, nil, nil, testNow); err != nil {
		t.Errorf("pubkey: %v", err)
	}
	if err := nipAZ.SweepAllowed(ctx, pk, malloryKy.Pub, nil, nil, nil, testNow); !errors.Is(err, nipAZ.ErrSweepRefused) {
		t.Errorf("pubkey, other claimant: %v", err)
	}
}

// T13-17: ResolveIdentity.
func TestT13_17_ResolveIdentity(t *testing.T) {
	ctx := context.Background()
	src, claims := attestedAlice(t)

	got, err := nipAZ.ResolveIdentity(ctx, githubID, ia1.Pub, claims, src, trustBoth, testNow)
	if err != nil || got != aliceKey.Pub {
		t.Errorf("ia = IA1: %q %v", got, err)
	}
	got, err = nipAZ.ResolveIdentity(ctx, githubID, "", claims, src, trustBoth, testNow)
	if err != nil || got != malloryKy.Pub {
		t.Errorf("no ia, latest trusted wins: %q %v", got, err)
	}

	// A 35521 whose content names another user_id, for another d, changes
	// nothing: the key is the caller's, never read from content.
	other := claimFor(t, malloryKy, attestOther(t, src))
	var content map[string]any
	_ = json.Unmarshal([]byte(other.Content), &content)
	content["user_id"] = githubUserID
	raw, _ := json.Marshal(content)
	other.Content = string(raw)
	if err := other.Sign(malloryKy.Priv); err != nil {
		t.Fatal(err)
	}
	got, err = nipAZ.ResolveIdentity(ctx, githubID, ia1.Pub, append(claims, other), src, trustBoth, testNow)
	if err != nil || got != aliceKey.Pub {
		t.Errorf("content spoof: %q %v", got, err)
	}

	// A pubkey resolves to itself with no lookup (a nil source is never used).
	if got, err := nipAZ.ResolveIdentity(ctx, nipAZ.Pubkey(recvKey.Pub), "", nil, nil, nil, testNow); err != nil || got != recvKey.Pub {
		t.Errorf("pubkey: %q %v", got, err)
	}

	// Unresolved: nothing attests the key through IA1.
	empty := newSource()
	if _, err := nipAZ.ResolveIdentity(ctx, githubID, ia1.Pub, nil, empty, trustBoth, testNow); !errors.Is(err, nipAZ.ErrUnresolved) {
		t.Errorf("unresolved: %v", err)
	}
	if _, err := nipAZ.ResolveIdentity(ctx, githubID, ia3.Pub, claims, src, trustBoth, testNow); !errors.Is(err, nipAZ.ErrUnresolved) {
		t.Errorf("untrusted ia: %v", err)
	}
	if _, err := nipAZ.ResolveIdentity(ctx, githubID, "", claims, src, nil, testNow); !errors.Is(err, nipAZ.ErrUnresolved) {
		t.Errorf("nil trust: %v", err)
	}
	// The platform is part of the identity.
	wrong := nipAZ.ResolvedConnection(nipAZ.ConnectionKey(githubCK), "gitlab")
	if _, err := nipAZ.ResolveIdentity(ctx, wrong, ia1.Pub, claims, src, trustBoth, testNow); !errors.Is(err, nipAZ.ErrUnresolved) {
		t.Errorf("other platform: %v", err)
	}
}

// attestOther has IA2 attest Mallory for another github account.
func attestOther(t *testing.T, src *fakeSource) *nipIC.Attestation {
	t.Helper()
	ev, err := nipIC.NewAttestation(nipIC.AttestationParams{
		PrivateKey: ia2.Priv, UserPubkey: malloryKy.Pub, Platform: "github", AuthType: "oauth",
		Evidence: nipIC.Evidence{UserID: "7654321", Username: "mallory"},
	})
	if err != nil {
		t.Fatal(err)
	}
	src.publish(ev)
	att, err := nipIC.ParseAttestation(ev)
	if err != nil {
		t.Fatal(err)
	}
	return att
}

// T13-15: r/R need the user's authorization.
func TestT13_15_LinkAuthorization(t *testing.T) {
	github := nipAZ.ResolvedConnection(nipAZ.ConnectionKey(githubCK), "github")
	req := buildRequest(t, nipAZ.AltZapRequestParams{Recipient: github, IA: ia1.Pub})
	f := receiptFor(t, req, zapAmount)

	for _, edit := range []func(*nipAZ.AltZapReceiptParams){
		func(p *nipAZ.AltZapReceiptParams) { p.ResolvedRecipientPubkey = aliceKey.Pub },
		func(p *nipAZ.AltZapReceiptParams) { p.ResolvedSenderPubkey = aliceKey.Pub },
	} {
		p := f.params
		edit(&p)
		if ev, err := nipAZ.NewAltZapReceipt(p); !errors.Is(err, nipAZ.ErrLinkNotAuthorized) || ev != nil {
			t.Errorf("unauthorized r/R: %v", err)
		}
	}

	// An indexed 35521 resolves the key, but without authorization the
	// server publishes the receipt without r.
	src, claims := attestedAlice(t)
	resolved, err := nipAZ.ResolveIdentity(context.Background(), github, ia1.Pub, claims, src, trustBoth, testNow)
	if err != nil || resolved != aliceKey.Pub {
		t.Fatalf("resolve: %q %v", resolved, err)
	}
	p := f.params
	ev, err := nipAZ.NewAltZapReceipt(p)
	if err != nil || tagValue(ev.Tags, "r") != "" {
		t.Fatalf("receipt without authorization: %v, r=%q", err, tagValue(ev.Tags, "r"))
	}
	p.ResolvedRecipientPubkey, p.LinkAuthorized = resolved, true
	ev, err = nipAZ.NewAltZapReceipt(p)
	if err != nil || tagValue(ev.Tags, "r") != aliceKey.Pub {
		t.Fatalf("authorized receipt: %v", err)
	}
	if r, err := nipAZ.ValidateAltZapReceipt(ev, receiptPolicy); err != nil || r.ResolvedPubkey != aliceKey.Pub {
		t.Errorf("authorized receipt validation: %v", err)
	}
}

// NIP-AZ §Terminology: a ConnectionKey never goes out with platform "nostr",
// which every receiver reads as a native pubkey; a native pubkey and a key on
// a NIP-IC platform still build.
func TestBuilders_RefuseNostrPlatformOnAKey(t *testing.T) {
	hashed := nipAZ.ResolvedConnection(nipAZ.ConnectionKey(githubCK), "nostr")
	base := nipAZ.AltZapRequestParams{PrivateKey: senderKey.Priv, Chain: "bitcoin", Lnurl: ownLnurl, AmountMloki: zapAmount, Relays: []string{testRelay}}
	p := base
	p.Recipient = hashed
	if ev, err := nipAZ.NewAltZapRequest(p); !errors.Is(err, nipAZ.ErrInvalidIdentityTag) || ev != nil {
		t.Errorf("9520 to a key on nostr: %v", err)
	}
	p.Recipient = nipAZ.Pubkey(recvKey.Pub)
	p.PrivateKey = proxyKey.Priv
	if ev, err := nipAZ.NewAltZapOnBehalfRequest(hashed, p); !errors.Is(err, nipAZ.ErrInvalidIdentityTag) || ev != nil {
		t.Errorf("9523 from a key on nostr: %v", err)
	}

	github := nipAZ.ResolvedConnection(nipAZ.ConnectionKey(githubCK), "github")
	req := buildRequest(t, nipAZ.AltZapRequestParams{Recipient: github, IA: ia1.Pub})
	f := receiptFor(t, req, zapAmount)
	rp := f.params
	rp.Recipient = hashed
	if ev, err := nipAZ.NewAltZapReceipt(rp); !errors.Is(err, nipAZ.ErrInvalidIdentityTag) || ev != nil {
		t.Errorf("9521 to a key on nostr: %v", err)
	}
	if _, err := nipAZ.NewAltZapReceipt(f.params); err != nil {
		t.Errorf("9521 to a key on github: %v", err)
	}

	native := buildRequest(t, nipAZ.AltZapRequestParams{})
	if got := native.Tags[0]; len(got) != 2 || got[1] != recvKey.Pub {
		t.Errorf("native p tag %v", got)
	}
	zr, err := nipAZ.ParseAltZapRequest(req)
	if err != nil || zr.Recipient.WebIdentity() != "github" || zr.Recipient.Value() != githubCK {
		t.Errorf("key on github: %v %v", zr, err)
	}
}
