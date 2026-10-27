package nip59_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip46"
	"github.com/ohstr/nmilat/nip59"
	"github.com/ohstr/nmilat/nipLS"
)

const (
	alicePriv = "0000000000000000000000000000000000000000000000000000000000000003"
	bobPriv   = "0000000000000000000000000000000000000000000000000000000000000005"
	malPriv   = "0000000000000000000000000000000000000000000000000000000000000007"
)

func key(t *testing.T, priv string) *nip46.LocalKey {
	t.Helper()
	k, err := nip46.NewLocalKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// countingOpener records each counterpart it decrypts for.
type countingOpener struct {
	*nip46.LocalKey
	peers []string
}

func (c *countingOpener) Decrypt(ctx context.Context, scheme, peer, ct string) (string, error) {
	c.peers = append(c.peers, peer)
	return c.LocalKey.Decrypt(ctx, scheme, peer, ct)
}

func sealAndWrap(t *testing.T, sender nip59.Sealer, to, content string) (*nip01.Event, *nip01.Event, *nip01.Event) {
	t.Helper()
	ctx := context.Background()
	rumor := nip01.NewEvent(14, content, []string{"p", to})
	rumor.CreatedAt = 1700000000
	seal, err := nip59.Seal(ctx, sender, rumor, to)
	if err != nil {
		t.Fatal(err)
	}
	wrap, err := nip59.WrapSeal(seal, to)
	if err != nil {
		t.Fatal(err)
	}
	return rumor, seal, wrap
}

func TestSealWrapUnwrapRoundTrip(t *testing.T) {
	alice, bob := key(t, alicePriv), key(t, bobPriv)
	rumor, seal, wrap := sealAndWrap(t, alice, bob.PubKey(), "hello bob")

	if wrap.Kind != nip59.KindGiftWrap || len(wrap.Tags) != 1 || wrap.Tags[0][1] != bob.PubKey() {
		t.Fatalf("wrap: %+v", wrap)
	}
	if wrap.PubKey == alice.PubKey() || seal.PubKey != alice.PubKey() || len(seal.Tags) != 0 {
		t.Fatal("wrap must hide the sender, seal must name it with no tags")
	}
	if rumor.Sig != "" || rumor.ID == "" {
		t.Fatal("rumor must be unsigned with an id")
	}

	got, err := nip59.Unwrap(context.Background(), bob, wrap, nip59.OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got.Sender != alice.PubKey() || got.Rumor.Content != "hello bob" || got.Rumor.ID != rumor.ID || got.Seal.ID != seal.ID {
		t.Fatalf("got %+v", got)
	}

	// The rumor travels without a "sig" field.
	plain, _ := bob.Decrypt(context.Background(), nip59.EncryptionNIP44V2, alice.PubKey(), seal.Content)
	if strings.Contains(plain, `"sig"`) {
		t.Fatalf("rumor carries sig: %s", plain)
	}

	// Only bob opens it.
	if _, err := nip59.Unwrap(context.Background(), key(t, malPriv), wrap, nip59.OpenOptions{}); err == nil {
		t.Fatal("a third party opened the wrap")
	}
}

func TestUnwrapSkipsForeignSenderUnread(t *testing.T) {
	alice, bob, mal := key(t, alicePriv), key(t, bobPriv), key(t, malPriv)
	_, malSeal, malWrap := sealAndWrap(t, mal, bob.PubKey(), "spam")

	opener := &countingOpener{LocalKey: bob}
	got, err := nip59.Unwrap(context.Background(), opener, malWrap, nip59.OpenOptions{From: []string{alice.PubKey()}})
	if !errors.Is(err, nip59.ErrForeignSender) {
		t.Fatalf("got %v", err)
	}
	if got.Rumor != nil || got.Seal.ID != malSeal.ID {
		t.Fatal("foreign seal must be returned unopened")
	}
	// One decrypt: the wrap, with its one-time key. Never the seal.
	if len(opener.peers) != 1 || opener.peers[0] != malWrap.PubKey {
		t.Fatalf("decrypted for %v", opener.peers)
	}

	// The listed sender is opened.
	_, _, aliceWrap := sealAndWrap(t, alice, bob.PubKey(), "hi")
	if _, err := nip59.Unwrap(context.Background(), bob, aliceWrap, nip59.OpenOptions{From: []string{strings.ToUpper(alice.PubKey())}}); err != nil {
		t.Fatal(err)
	}
}

// badSeal seals rumorJSON as alice, as a hostile sender would.
func badSeal(t *testing.T, rumorJSON string) *nip01.Event {
	t.Helper()
	alice, bob := key(t, alicePriv), key(t, bobPriv)
	ct, err := alice.Encrypt(context.Background(), nip59.EncryptionNIP44V2, bob.PubKey(), rumorJSON)
	if err != nil {
		t.Fatal(err)
	}
	seal := nip01.NewEvent(nip59.KindSeal, ct)
	seal.Tags = [][]string{}
	if err := alice.Sign(context.Background(), seal); err != nil {
		t.Fatal(err)
	}
	return seal
}

func TestUnwrapRefusesBadRumors(t *testing.T) {
	alice, bob, mal := key(t, alicePriv), key(t, bobPriv), key(t, malPriv)
	good := nip01.NewEvent(14, "x")
	if err := nip59.PrepareRumor(good, alice.PubKey()); err != nil {
		t.Fatal(err)
	}

	wrongID := *good
	wrongID.Content = "changed after hashing"
	b, _ := json.Marshal(wrongID)
	if _, err := nip59.Unwrap(context.Background(), bob, badSeal(t, string(b)), nip59.OpenOptions{}); err == nil || !strings.Contains(err.Error(), "rumor id") {
		t.Fatalf("bad rumor id: %v", err)
	}

	impostor := nip01.NewEvent(14, "I am mal")
	_ = nip59.PrepareRumor(impostor, mal.PubKey())
	b, _ = json.Marshal(impostor)
	if _, err := nip59.Unwrap(context.Background(), bob, badSeal(t, string(b)), nip59.OpenOptions{}); err == nil || !strings.Contains(err.Error(), "claims author") {
		t.Fatalf("author mismatch: %v", err)
	}

	// A seal whose signature is broken is refused before decrypting.
	seal := badSeal(t, `{}`)
	seal.Content += "x"
	opener := &countingOpener{LocalKey: bob}
	if _, err := nip59.Unwrap(context.Background(), opener, seal, nip59.OpenOptions{}); err == nil || len(opener.peers) != 0 {
		t.Fatalf("forged seal: %v, decrypted %v", err, opener.peers)
	}
}

// The legacy Wrap's output still opens.
func TestUnwrapOpensLegacyWrap(t *testing.T) {
	alice, bob := key(t, alicePriv), key(t, bobPriv)
	wrap, err := nip59.Wrap(nip01.NewUnsignedEvent(14, alice.PubKey(), "old"), alicePriv, bob.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	got, err := nip59.Unwrap(context.Background(), bob, wrap, nip59.OpenOptions{})
	if err != nil || got.Rumor.Content != "old" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestProveAndVerify(t *testing.T) {
	alice, bob := key(t, alicePriv), key(t, bobPriv)
	rumor, seal, _ := sealAndWrap(t, alice, bob.PubKey(), "I owe you 5")

	// Either party can prove it: the recipient with the sender as
	// counterpart, the sender with the recipient.
	for name, p := range map[string]func() (*nip59.Proof, error){
		"recipient": func() (*nip59.Proof, error) { return nip59.Prove(context.Background(), bob, seal, alice.PubKey()) },
		"sender":    func() (*nip59.Proof, error) { return nip59.Prove(context.Background(), alice, seal, bob.PubKey()) },
	} {
		proof, err := p()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		// Through JSON, as a third party receives it.
		b, _ := json.Marshal(proof)
		var back nip59.Proof
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		got, err := nip59.VerifyProof(&back, alice.PubKey())
		if err != nil || got.Content != "I owe you 5" || got.ID != rumor.ID {
			t.Fatalf("%s: %+v %v", name, got, err)
		}
		if _, err := nip59.VerifyProof(&back, bob.PubKey()); err == nil {
			t.Fatalf("%s: verified as the wrong author", name)
		}
	}
}

func TestVerifyProofRefusesAnyChange(t *testing.T) {
	alice, bob, mal := key(t, alicePriv), key(t, bobPriv), key(t, malPriv)
	_, seal, _ := sealAndWrap(t, alice, bob.PubKey(), "exact words")
	proof, err := nip59.Prove(context.Background(), bob, seal, alice.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(proof)

	// Flip each hex/base64 character of the seal and keys in turn.
	s := string(raw)
	for i := 0; i < len(s); i++ {
		c := s[i]
		var r byte
		switch {
		case c >= 'a' && c <= 'e', c >= 'A' && c <= 'Y', c >= '0' && c <= '8':
			r = c + 1
		default:
			continue
		}
		mut := s[:i] + string(r) + s[i+1:]
		var p nip59.Proof
		if json.Unmarshal([]byte(mut), &p) != nil {
			continue
		}
		if rumor, err := nip59.VerifyProof(&p, alice.PubKey()); err == nil && rumor.Content == "exact words" && mut != s {
			// A change that leaves seal and keys byte-identical (e.g. a JSON
			// key name) is not a change to the proof.
			if p.Seal.ID == proof.Seal.ID && p.Seal.Sig == proof.Seal.Sig && p.Seal.Content == proof.Seal.Content &&
				string(p.Keys.ChaChaKey) == string(proof.Keys.ChaChaKey) && string(p.Keys.HMACKey) == string(proof.Keys.HMACKey) &&
				string(p.Keys.ChaChaNonce) == string(proof.Keys.ChaChaNonce) {
				continue
			}
			t.Fatalf("changed byte %d still verifies", i)
		}
	}

	// A foreign seal with valid keys of its own does not verify as alice.
	_, malSeal, _ := sealAndWrap(t, mal, bob.PubKey(), "forged")
	malProof, _ := nip59.Prove(context.Background(), bob, malSeal, mal.PubKey())
	if _, err := nip59.VerifyProof(malProof, alice.PubKey()); err == nil {
		t.Fatal("foreign seal verified")
	}
	// Alice's seal with another seal's keys does not open.
	mixed := &nip59.Proof{Seal: seal, Keys: malProof.Keys}
	if _, err := nip59.VerifyProof(mixed, alice.PubKey()); err == nil {
		t.Fatal("other keys opened the seal")
	}
}

// Seal, Unwrap and Prove work through a socket signer that holds the key.
func TestThroughSocketSigner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bob := key(t, bobPriv)

	dir, err := os.MkdirTemp("", "nip59")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	srv, err := nipLS.NewServer(nipLS.ServerConfig{Key: key(t, alicePriv), Policy: nipLS.AllowAll})
	if err != nil {
		t.Fatal(err)
	}
	l, err := nipLS.Listen(path, nipLS.ListenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, l) }()
	t.Cleanup(func() { cancel(); <-done })

	alice, err := nipLS.Dial(ctx, nipLS.FormatURI(path))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = alice.Close() }()

	_, seal, wrap := sealAndWrap(t, alice, bob.PubKey(), "via socket")
	got, err := nip59.Unwrap(ctx, bob, wrap, nip59.OpenOptions{})
	if err != nil || got.Sender != alice.PubKey() {
		t.Fatalf("%+v %v", got, err)
	}
	// Alice proves her own sent message through the socket.
	proof, err := nip59.Prove(ctx, alice, seal, bob.PubKey())
	if err != nil {
		t.Fatal(err)
	}
	if r, err := nip59.VerifyProof(proof, alice.PubKey()); err != nil || r.Content != "via socket" {
		t.Fatalf("%v", err)
	}
	// And opens a reply through it.
	_, _, reply := sealAndWrap(t, bob, alice.PubKey(), "got it")
	back, err := nip59.Unwrap(ctx, alice, reply, nip59.OpenOptions{From: []string{bob.PubKey()}})
	if err != nil || back.Rumor.Content != "got it" {
		t.Fatalf("%v", err)
	}
}
