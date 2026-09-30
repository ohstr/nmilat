package nipcash

import (
	"bytes"

	"encoding/hex"
	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
	"strings"
	"testing"
)

// The hub-group fingerprint (TLV type 7).
//
// It exists because nothing else in a token says which Cash Hub issued it. Mint
// provenance identifies the minting NODE, and one node routinely runs several Hubs,
// so grouping bills by minter merges ones the Hub then refuses — which is what a
// holder experiences as "consolidate just fails".
//
// Every test here turns on the same distinction: this field is a grouping HINT, not
// an authorization input. That is what makes 4 unauthenticated bytes acceptable, and
// it is also why a malformed one must never cost a holder access to their bill.

func sampleToken(t *testing.T, hubGroup []byte) Token {
	t.Helper()
	amt := uint64(123456)
	return Token{
		HRP:                  "lokicash",
		WalletPubkey:         hex.EncodeToString(bytes.Repeat([]byte{0xab}, 32)),
		Secret:               hex.EncodeToString(bytes.Repeat([]byte{0xcd}, 32)),
		RelayURLs:            []string{"wss://relay.example.com"},
		MintSignature:        bytes.Repeat([]byte{0x01}, mintSigLen),
		AttestedAmountMillis: &amt,
		HubGroup:             hubGroup,
	}
}

func TestHubGroup_RoundTrips(t *testing.T) {
	fp := HubGroupFor("hub-pubkey-aaa")
	if len(fp) != HubGroupLen {
		t.Fatalf("HubGroupFor returned %d bytes, want %d", len(fp), HubGroupLen)
	}

	encoded, err := Encode(sampleToken(t, fp))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !bytes.Equal(decoded.HubGroup, fp) {
		t.Errorf("HubGroup = %x, want %x", decoded.HubGroup, fp)
	}
	// The provenance pair must be unaffected by the new field.
	if !decoded.HasProvenance() {
		t.Error("adding a hub group lost the mint provenance")
	}
}

// The size claim, asserted rather than assumed: the fingerprint is worth having only
// if it is nearly free, so a change that made it expensive should fail here.
func TestHubGroup_CostsAboutTenCharacters(t *testing.T) {
	without, err := Encode(sampleToken(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	with, err := Encode(sampleToken(t, HubGroupFor("hub-pubkey-aaa")))
	if err != nil {
		t.Fatal(err)
	}
	grew := len(with) - len(without)
	if grew > 12 {
		t.Errorf("hub group added %d characters (%d -> %d); it is a grouping hint and must stay nearly free",
			grew, len(without), len(with))
	}
	t.Logf("token %d -> %d characters (+%d)", len(without), len(with), grew)
}

func TestHubGroupFor_IsStableAndDistinct(t *testing.T) {
	a1 := HubGroupFor("hub-a")
	a2 := HubGroupFor("hub-a")
	b := HubGroupFor("hub-b")

	if !bytes.Equal(a1, a2) {
		t.Error("HubGroupFor is not deterministic; the same Hub must stamp the same fingerprint on every bill")
	}
	if bytes.Equal(a1, b) {
		t.Error("two different Hubs produced the same fingerprint")
	}
	// It must not be the input in the clear — every bill a Hub mints carries this.
	if strings.Contains(hex.EncodeToString(a1), hex.EncodeToString([]byte("hub-a"))) {
		t.Error("the fingerprint leaks the Hub identifier verbatim")
	}
}

// TestSameHubGroup_MissingIsNeverAWildcard is the rule that keeps this from
// recreating the bug it replaces.
//
// Bills with no fingerprint must NOT group together. Treating "unknown" as "same"
// is exactly how grouping by minter went wrong: it merged bills that merely shared a
// node, and the Hub refused the lot.
func TestSameHubGroup_MissingIsNeverAWildcard(t *testing.T) {
	fp := HubGroupFor("hub-a")
	withFP := sampleToken(t, fp)
	without := sampleToken(t, nil)
	other := sampleToken(t, HubGroupFor("hub-b"))
	short := sampleToken(t, []byte{0x01, 0x02})

	if !SameHubGroup(withFP, withFP) {
		t.Error("a bill must group with itself")
	}
	if SameHubGroup(withFP, other) {
		t.Error("bills from different Hubs must not group")
	}
	if SameHubGroup(without, without) {
		t.Error("two bills with NO fingerprint must not group — unknown is not a wildcard")
	}
	if SameHubGroup(withFP, without) {
		t.Error("a known and an unknown Hub must not group")
	}
	if SameHubGroup(short, short) {
		t.Error("a wrong-length fingerprint must not group")
	}
}

// TestHubGroup_AnomaliesLeaveTheTokenUsable is the safety property.
//
// A bad fingerprint must cost a holder nothing but grouping. Failing the decode would
// let a cosmetic field strand real value: the bill is still perfectly spendable one
// at a time, and a token whose checksum verifies would become unopenable.
func TestHubGroup_AnomaliesLeaveTheTokenUsable(t *testing.T) {
	// Encode refuses to CREATE a wrong-length one — a producer's bug should surface
	// at the producer.
	if _, err := Encode(sampleToken(t, []byte{0x01, 0x02})); err == nil {
		t.Error("Encode accepted a wrong-length hub group; a producer must not emit one")
	}

	// But a DECODER meeting one drops it and keeps going. Built by hand, since
	// Encode will not produce it.
	for _, tc := range []struct {
		name  string
		value []byte
		dup   bool
	}{
		{name: "too short", value: []byte{0x01}},
		{name: "too long", value: bytes.Repeat([]byte{0x01}, 8)},
		{name: "empty", value: []byte{}},
		{name: "duplicated", value: HubGroupFor("hub-a"), dup: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := handBuiltToken(t, tc.value, tc.dup)
			decoded, err := Decode(raw)
			if err != nil {
				t.Fatalf("a malformed hub group must not fail the decode — the bill is still spendable: %v", err)
			}
			if decoded.HubGroup != nil {
				t.Errorf("HubGroup = %x, want nil (dropped)", decoded.HubGroup)
			}
			// And the rest of the token survives intact.
			if decoded.WalletPubkey == "" || decoded.Secret == "" || !decoded.HasProvenance() {
				t.Error("dropping a bad hub group damaged the rest of the token")
			}
		})
	}
}

// handBuiltToken assembles a token whose hub-group TLV Encode would refuse to
// produce, so the DECODER's tolerance can be tested. Everything else is valid.
func handBuiltToken(t *testing.T, hubGroup []byte, duplicate bool) string {
	t.Helper()
	buf := &bytes.Buffer{}
	writeTLV(buf, tlvWalletPubkey, bytes.Repeat([]byte{0xab}, keyLen))
	writeTLV(buf, tlvRelay, []byte("wss://relay.example.com"))
	writeTLV(buf, tlvSecret, bytes.Repeat([]byte{0xcd}, keyLen))
	writeTLV(buf, tlvMintSignature, bytes.Repeat([]byte{0x01}, mintSigLen))
	var amt [attestedAmountLen]byte
	amt[7] = 42
	writeTLV(buf, tlvAttestedAmount, amt[:])
	writeTLV(buf, tlvHubGroup, hubGroup)
	if duplicate {
		writeTLV(buf, tlvHubGroup, hubGroup)
	}

	bits5, err := bech32.ConvertBits(buf.Bytes(), 8, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := bech32.Encode("lokicash", bits5)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
