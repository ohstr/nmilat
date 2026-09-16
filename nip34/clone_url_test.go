package nip34

import (
	"errors"
	"testing"

	"github.com/ohstr/nmilat/nip19"
)

func TestParseCloneURL_NAddrForm(t *testing.T) {
	c, err := ParseCloneURL("nostr://naddr1qexamplevalue")
	if err != nil {
		t.Fatalf("ParseCloneURL() error = %v", err)
	}
	if c.NAddr != "naddr1qexamplevalue" {
		t.Errorf("NAddr = %q", c.NAddr)
	}
	if c.Owner != "" || c.Identifier != "" {
		t.Errorf("expected empty Owner/Identifier, got %+v", c)
	}
}

func TestParseCloneURL_OwnerIdentifierForm(t *testing.T) {
	c, err := ParseCloneURL("nostr://npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/my%20%F0%9F%9A%80%20repo")
	if err != nil {
		t.Fatalf("ParseCloneURL() error = %v", err)
	}
	if c.Owner != "npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr" {
		t.Errorf("Owner = %q", c.Owner)
	}
	if c.Identifier != "my \U0001F680 repo" {
		t.Errorf("Identifier = %q", c.Identifier)
	}
	if c.RelayHint != "" {
		t.Errorf("RelayHint = %q, want empty", c.RelayHint)
	}
}

func TestParseCloneURL_OwnerRelayIdentifierForm(t *testing.T) {
	c, err := ParseCloneURL("nostr://npub15qydau2hjma6ngxkl2cyar74wzyjshvl65za5k5rl69264ar2exs5cyejr/relay.ngit.dev/ngit")
	if err != nil {
		t.Fatalf("ParseCloneURL() error = %v", err)
	}
	if c.RelayHint != "relay.ngit.dev" || c.Identifier != "ngit" {
		t.Errorf("RelayHint/Identifier = %q/%q", c.RelayHint, c.Identifier)
	}
}

func TestParseCloneURL_Errors(t *testing.T) {
	if _, err := ParseCloneURL("https://example.com"); !errors.Is(err, ErrInvalidCloneURL) {
		t.Errorf("missing scheme: error = %v, want ErrInvalidCloneURL", err)
	}
	if _, err := ParseCloneURL("nostr://a/b/c/d"); !errors.Is(err, ErrInvalidCloneURL) {
		t.Errorf("too many segments: error = %v, want ErrInvalidCloneURL", err)
	}
}

func TestBuildCloneURL_RoundTrip(t *testing.T) {
	raw := BuildCloneURL("danconwaydev.com", "ws://localhost:7334", "my-local-only-repo")
	c, err := ParseCloneURL(raw)
	if err != nil {
		t.Fatalf("ParseCloneURL() error = %v", err)
	}
	if c.Owner != "danconwaydev.com" || c.RelayHint != "ws://localhost:7334" || c.Identifier != "my-local-only-repo" {
		t.Errorf("round trip = %+v", c)
	}
}

func TestCloneURL_ResolveAddr(t *testing.T) {
	naddr, err := nip19.EncodeAddr(nip19.EntityPointer{
		Identifier: "ngit",
		PublicKey:  ownerPubkey,
		Kind:       KindRepositoryAnnouncement,
		Relays:     []string{"wss://relay.ngit.dev"},
	})
	if err != nil {
		t.Fatalf("nip19.EncodeAddr() error = %v", err)
	}

	c, err := ParseCloneURL(BuildCloneURLFromAddr(naddr))
	if err != nil {
		t.Fatalf("ParseCloneURL() error = %v", err)
	}

	p, err := c.ResolveAddr()
	if err != nil {
		t.Fatalf("ResolveAddr() error = %v", err)
	}
	if p.Identifier != "ngit" || p.PublicKey != ownerPubkey || p.Kind != KindRepositoryAnnouncement {
		t.Errorf("ResolveAddr() = %+v", p)
	}
}

func TestCloneURL_ResolveAddr_NotNAddrForm(t *testing.T) {
	c := &CloneURL{Owner: "npub1...", Identifier: "ngit"}
	if _, err := c.ResolveAddr(); !errors.Is(err, ErrInvalidCloneURL) {
		t.Errorf("error = %v, want ErrInvalidCloneURL", err)
	}
}
