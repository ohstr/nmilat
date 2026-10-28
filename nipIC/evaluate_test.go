package nipIC

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	btcec "github.com/flokiorg/go-flokicoin/crypto"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

type keypair struct{ priv, pub string }

func newKeypair(t *testing.T) keypair {
	t.Helper()
	k, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	priv := hex.EncodeToString(k.Serialize())
	pub, _ := utils.GetPublicKey(priv)
	return keypair{priv, pub}
}

// fakeSource is a relay set the test controls.
type fakeSource struct {
	events      map[string]*nip01.Event
	current     map[string]string // ia+key → id
	deleted     map[string]bool
	unreachable bool
}

func newSource() *fakeSource {
	return &fakeSource{events: map[string]*nip01.Event{}, current: map[string]string{}, deleted: map[string]bool{}}
}

func (s *fakeSource) publish(ev *nip01.Event) {
	s.events[ev.ID] = ev
	if ev.Kind == KindAttestation {
		for _, tag := range ev.Tags {
			if tag[0] == TagDTag {
				s.current[ev.PubKey+tag[1]] = ev.ID
			}
		}
	}
}

func (s *fakeSource) Fetch(_ context.Context, ref AttestationRef) (*nip01.Event, error) {
	if s.unreachable {
		return nil, errors.New("unreachable")
	}
	return s.events[ref.EventID], nil
}

func (s *fakeSource) Current(_ context.Context, ia string, key ConnectionKey) (string, error) {
	return s.current[ia+string(key)], nil
}

func (s *fakeSource) DeletedByAuthor(_ context.Context, _ string, id string) (bool, error) {
	return s.deleted[id], nil
}

const evalUserID = "80351110224678912"

func attest(t *testing.T, ia keypair, user string, mutate ...func(*AttestationParams)) *Attestation {
	t.Helper()
	p := AttestationParams{PrivateKey: ia.priv, UserPubkey: user, Platform: "discord", AuthType: "email_code",
		Evidence: Evidence{UserID: evalUserID, Username: "alice"}}
	for _, m := range mutate {
		m(&p)
	}
	ev, err := NewAttestation(p)
	if err != nil {
		t.Fatal(err)
	}
	att, err := ParseAttestation(ev)
	if err != nil {
		t.Fatal(err)
	}
	return att
}

func claim(t *testing.T, user keypair, atts ...*Attestation) *nip01.Event {
	t.Helper()
	var links []AttestationLink
	for _, a := range atts {
		links = append(links, AttestationLink{Attestation: a, Relay: "wss://ia.example"})
	}
	ev, err := NewIdentityConnection(user.priv, links, Profile{DisplayName: "Alice"})
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// resign rebuilds a 35522 with changed fields, signed by signer.
func resign(t *testing.T, a *Attestation, signer keypair, edit func(*nip01.Event)) *Attestation {
	t.Helper()
	ev := &nip01.Event{Kind: a.Kind, CreatedAt: a.CreatedAt, Content: a.Content}
	for _, tag := range a.Tags {
		ev.Tags = append(ev.Tags, append([]string(nil), tag...))
	}
	edit(ev)
	if err := ev.Sign(signer.priv); err != nil {
		t.Fatal(err)
	}
	out, err := ParseAttestation(ev)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func setTag(ev *nip01.Event, name, value string) {
	for _, tag := range ev.Tags {
		if tag[0] == name {
			tag[1] = value
		}
	}
}

// T05-10, T05-11, T05-12, T05-24: the verification model, case by case.
func TestT05_10_Evaluate(t *testing.T) {
	ia1, ia2, alice, mallory := newKeypair(t), newKeypair(t), newKeypair(t), newKeypair(t)
	key, _ := NewConnectionKey("discord", evalUserID)
	now := time.Now()
	trustBoth := func(ia string) bool { return ia == ia1.pub || ia == ia2.pub }
	run := func(src *fakeSource, claims ...*nip01.Event) []Verdict {
		return Evaluate(context.Background(), key, claims, src, trustBoth, now)
	}

	if v := run(newSource()); len(v) != 1 || v[0].State != Unverified {
		t.Fatalf("no claim: %+v", v)
	}

	good := attest(t, ia1, alice.pub)
	src := newSource()
	src.publish(good.Event)
	if v := run(src, claim(t, alice, good)); v[0].State != Verified || v[0].Attestation.ID != good.ID {
		t.Fatalf("good: %+v", v)
	}

	spoofed := func(name string, src *fakeSource, c *nip01.Event) {
		t.Helper()
		if v := run(src, c); len(v) != 1 || v[0].State != Spoofed {
			t.Errorf("%s: %+v", name, v)
		}
	}
	// Untrusted IA, self-attestation.
	stranger := newKeypair(t)
	untrusted := attest(t, stranger, alice.pub)
	src = newSource()
	src.publish(untrusted.Event)
	spoofed("untrusted IA", src, claim(t, alice, untrusted))

	// A claim whose signature fails names no pubkey.
	forged := claim(t, alice, good)
	forged.Content += " "
	if v := run(src, forged); len(v) != 1 || v[0].State != Spoofed || v[0].Pubkey != "" {
		t.Errorf("bad signature: %+v", v)
	}
	self := attest(t, alice, alice.pub)
	src = newSource()
	src.publish(self.Event)
	spoofed("self-attested", src, claimTrusting(t, alice, self))

	// p, d and platform mismatches: Mallory points at Alice's attestation.
	src = newSource()
	src.publish(good.Event)
	spoofed("p mismatch", src, rawClaim(t, mallory, string(key), "discord", good.ID))
	other := attest(t, ia1, mallory.pub, func(p *AttestationParams) { p.Evidence.UserID = "12345" })
	src.publish(other.Event)
	spoofed("d mismatch", src, rawClaim(t, mallory, string(key), "discord", other.ID))
	wrongPlatform := resign(t, good, ia1, func(ev *nip01.Event) { setTag(ev, TagPlatform, "x") })
	src.publish(wrongPlatform.Event)
	spoofed("platform mismatch", src, rawClaim(t, alice, string(key), "discord", wrongPlatform.ID))

	// Expired; deleted by its IA; deleted by Mallory (ignored); stale; unreachable.
	expired := resign(t, good, ia1, func(ev *nip01.Event) { setTag(ev, TagExpiration, strconv.FormatInt(now.Unix()-1, 10)) })
	src = newSource()
	src.publish(expired.Event)
	spoofed("expired", src, rawClaim(t, alice, string(key), "discord", expired.ID))
	src = newSource()
	src.publish(good.Event)
	src.deleted[good.ID] = true
	spoofed("deleted by IA", src, claim(t, alice, good))
	src = newSource()
	src.publish(good.Event)
	newer := resign(t, good, ia1, func(ev *nip01.Event) { ev.CreatedAt++ })
	src.publish(newer.Event)
	spoofed("stale", src, claim(t, alice, good))
	src = newSource()
	src.publish(good.Event)
	src.unreachable = true
	spoofed("unreachable", src, claim(t, alice, good))
	src = newSource()
	src.publish(good.Event)
	spoofed("id ≠ reference", src, rawClaim(t, alice, string(key), "discord", newer.ID))

	// 901 s ahead does not count; 600 s ahead does.
	for ahead, want := range map[int64]VerificationState{901: Spoofed, 600: Verified} {
		future := resign(t, good, ia1, func(ev *nip01.Event) { ev.CreatedAt = uint64(now.Unix() + ahead) })
		src = newSource()
		src.publish(future.Event)
		if v := run(src, claim(t, alice, future)); v[0].State != want {
			t.Errorf("%d s ahead: %v", ahead, v[0].State)
		}
	}

	// Two references, one good: Verified (and either IA alone suffices).
	g2 := attest(t, ia2, alice.pub)
	src = newSource()
	src.publish(good.Event)
	src.publish(g2.Event)
	c2 := claim(t, alice, untrusted, g2)
	if v := run(src, c2); v[0].State != Verified {
		t.Errorf("two refs, one good: %+v", v)
	}

	// IA1 names A at T, IA2 names B at T+10: B Verified, A Spoofed.
	bob := newKeypair(t)
	forBob := resign(t, attest(t, ia2, bob.pub), ia2, func(ev *nip01.Event) { ev.CreatedAt = good.CreatedAt + 10 })
	src = newSource()
	src.publish(good.Event)
	src.publish(forBob.Event)
	v := run(src, claim(t, alice, good), claim(t, bob, forBob))
	if v[0].State != Spoofed || v[1].State != Verified {
		t.Errorf("transfer: alice %v bob %v", v[0].State, v[1].State)
	}
	// A future-dated attestation for Mallory takes no part: Alice stays Verified.
	future := resign(t, attest(t, ia2, mallory.pub), ia2, func(ev *nip01.Event) { ev.CreatedAt = uint64(now.Unix() + 5000) })
	src = newSource()
	src.publish(good.Event)
	src.publish(future.Event)
	v = run(src, claim(t, alice, good), claim(t, mallory, future))
	if v[0].State != Verified || v[1].State != Spoofed {
		t.Errorf("future-dated mallory: %v %v", v[0].State, v[1].State)
	}

	// T05-11: content naming another user id is a mismatch, Spoofed.
	src = newSource()
	src.publish(good.Event)
	lying := rawClaimContent(t, alice, string(key), "discord", `{"user_id":"999"}`, good.ID)
	if v := run(src, lying); v[0].State != Spoofed || len(v[0].Reasons) == 0 {
		t.Errorf("content mismatch: %+v", v)
	}
	// T05-12: a 35522 embedded in content counts for nothing.
	src = newSource()
	raw, _ := json.Marshal(good.Event)
	embedded := rawClaimContent(t, alice, string(key), "discord", string(raw), "0000")
	spoofed("embedded attestation", src, embedded)
}

func claimTrusting(t *testing.T, user keypair, a *Attestation) *nip01.Event {
	return rawClaim(t, user, string(a.ConnectionKey), string(a.Platform), a.ID)
}

func rawClaim(t *testing.T, user keypair, d, platform string, refs ...string) *nip01.Event {
	return rawClaimContent(t, user, d, platform, "", refs...)
}

func rawClaimContent(t *testing.T, user keypair, d, platform, content string, refs ...string) *nip01.Event {
	t.Helper()
	ev := &nip01.Event{Kind: KindIdentityConnection, CreatedAt: uint64(time.Now().Unix()), Content: content,
		Tags: [][]string{{TagDTag, d}, {TagPlatform, platform}}}
	for _, r := range refs {
		ev.Tags = append(ev.Tags, []string{TagEventRef, r, "wss://ia.example"})
	}
	if err := ev.Sign(user.priv); err != nil {
		t.Fatal(err)
	}
	return ev
}

// T05-24: NewIdentityConnection refuses mixed accounts, a foreign p and a non-ws
// relay; it references, never embeds.
func TestT05_24_NewIdentityConnection(t *testing.T) {
	ia, alice, bob := newKeypair(t), newKeypair(t), newKeypair(t)
	good := attest(t, ia, alice.pub)
	ev := claim(t, alice, good)
	c, err := ParseIdentityConnection(ev)
	if err != nil || c.Attestations[0].EventID != good.ID || c.Platform != "discord" {
		t.Fatalf("%+v %v", c, err)
	}
	if ev.Content != `{"display_name":"Alice","user_id":"80351110224678912","username":"alice"}` {
		t.Errorf("content %s", ev.Content)
	}
	other := attest(t, ia, alice.pub, func(p *AttestationParams) { p.Evidence.UserID = "12345" })
	for name, links := range map[string][]AttestationLink{
		"mixed d":     {{good, "wss://a"}, {other, "wss://a"}},
		"foreign p":   {{attest(t, ia, bob.pub), "wss://a"}},
		"https relay": {{good, "https://a"}},
		"none":        nil,
	} {
		if _, err := NewIdentityConnection(alice.priv, links, Profile{}); err == nil {
			t.Errorf("%s: signed", name)
		}
	}
}

// T05-07, T05-08, T05-21, T05-22.
func TestT05_22_AttestationStrictness(t *testing.T) {
	ia, alice := newKeypair(t), newKeypair(t)
	if _, err := NewAttestation(AttestationParams{PrivateKey: ia.priv, UserPubkey: alice.pub, Platform: "discord",
		AuthType: "email_code", Evidence: Evidence{UserID: "080351110224678912"}}); !errors.Is(err, ErrNotCanonical) {
		t.Errorf("leading zero: %v", err)
	}
	if a := attest(t, ia, alice.pub); a.ConnectionKey != "22ced17fc7b3a6f7262d2dbe00b42d302948595468e025f4392b0a5022b8319d" {
		t.Errorf("d %s", a.ConnectionKey)
	}
	for _, p := range []WebIdentity{"Discord", "git:hub", "git hub", ""} {
		if _, err := NewAttestation(AttestationParams{PrivateKey: ia.priv, UserPubkey: alice.pub, Platform: p,
			AuthType: "email_code", Evidence: Evidence{UserID: "1"}}); !errors.Is(err, ErrPlatformName) {
			t.Errorf("platform %q: %v", p, err)
		}
	}
	good := attest(t, ia, alice.pub)
	for name, edit := range map[string]func(*nip01.Event){
		"duplicate d":        func(ev *nip01.Event) { ev.Tags = append(ev.Tags, []string{TagDTag, string(good.ConnectionKey)}) },
		"duplicate p":        func(ev *nip01.Event) { ev.Tags = append(ev.Tags, []string{TagRecipient, alice.pub}) },
		"duplicate platform": func(ev *nip01.Event) { ev.Tags = append(ev.Tags, []string{TagPlatform, "discord"}) },
		"duplicate evidence": func(ev *nip01.Event) { ev.Tags = append(ev.Tags, ev.Tags[3]) },
		"duplicate exp":      func(ev *nip01.Event) { ev.Tags = append(ev.Tags, []string{TagExpiration, "1"}) },
		"prefixed d":         func(ev *nip01.Event) { setTag(ev, TagDTag, "discord:"+string(good.ConnectionKey)) },
		"uppercase d":        func(ev *nip01.Event) { setTag(ev, TagDTag, "A"+string(good.ConnectionKey)[1:]) },
		"bad expiration":     func(ev *nip01.Event) { setTag(ev, TagExpiration, "soon") },
		"content":            func(ev *nip01.Event) { ev.Content = "x" },
		"version 2":          func(ev *nip01.Event) { setTag(ev, TagEvidence, `{"version":2,"auth_type":"email_code"}`) },
		"no version":         func(ev *nip01.Event) { setTag(ev, TagEvidence, `{"auth_type":"email_code"}`) },
		"empty auth_type":    func(ev *nip01.Event) { setTag(ev, TagEvidence, `{"version":1,"auth_type":""}`) },
		"public_post bare": func(ev *nip01.Event) {
			setTag(ev, TagEvidence, `{"version":1,"auth_type":"public_post","evidence_url":"u","challenge":"c"}`)
		},
	} {
		ev := &nip01.Event{Kind: good.Kind, CreatedAt: good.CreatedAt, Content: good.Content}
		for _, tag := range good.Tags {
			ev.Tags = append(ev.Tags, append([]string(nil), tag...))
		}
		edit(ev)
		if err := ev.Sign(ia.priv); err != nil {
			t.Fatal(err)
		}
		if _, err := ParseAttestation(ev); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	if err := good.Reverify(); !errors.Is(err, ErrNotReverifiable) {
		t.Errorf("email_code Reverify: %v", err)
	}
	// K-NPV-1 evidence re-verifies; the same challenge under another p does not.
	const pub = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	tok, _ := NewChallengeToken(pub, "123456")
	pp := attest(t, ia, pub, func(p *AttestationParams) {
		p.AuthType = ""
		p.Evidence.EvidenceURL, p.Evidence.Challenge, p.Evidence.PreAuthCode = "https://x/1", tok, "123456"
	})
	if err := pp.Reverify(); err != nil {
		t.Errorf("K-NPV-1 Reverify: %v", err)
	}
	replay := attest(t, ia, alice.pub, func(p *AttestationParams) {
		p.AuthType = ""
		p.Evidence.EvidenceURL, p.Evidence.Challenge, p.Evidence.PreAuthCode = "https://x/1", tok, "123456"
	})
	if err := replay.Reverify(); err == nil {
		t.Error("a challenge replayed under another pubkey re-verified")
	}
}

// T05-13, T05-14 (K-NPV-1).
func TestT05_13_Npv1(t *testing.T) {
	const pub = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	tok, err := NewChallengeToken(pub, "123456")
	if err != nil || tok != "npv11qqst2amnrkxw504due908pjrhhwec973xuvtzssacascag7hfndk9xsn78h2f" {
		t.Fatalf("token %s %v", tok, err)
	}
	h, _ := tok.decode()
	if hex.EncodeToString(h) != "b577731d8cea3eade64af38643bddd9c17d13718b1421dc7618ea3d74cdb629a" {
		t.Errorf("hash %x", h)
	}
	if err := tok.Verify(pub, "123456 "); err == nil {
		t.Error("a changed code verified")
	}
	if err := tok.Verify("c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", "123456"); err == nil {
		t.Error("another pubkey verified")
	}
	for name, payload := range map[string][]byte{
		"33 bytes":    append([]byte{0, 0x20}, h[:31]...),
		"type 1":      append([]byte{1, 0x20}, h...),
		"length 0x1f": append([]byte{0, 0x1f}, h...),
	} {
		bad := encodeNpv(t, "npv1", payload)
		if err := bad.Verify(pub, "123456"); !errors.Is(err, ErrInvalidChallengeToken) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := encodeNpv(t, "npv2", append([]byte{0, 0x20}, h...)).Verify(pub, "123456"); !errors.Is(err, ErrInvalidChallengeToken) {
		t.Errorf("wrong HRP: %v", err)
	}
}
