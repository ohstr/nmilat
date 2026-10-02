package nipcash

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// auditB_priv: the hub-group fingerprint is sha256(hub AppPubkey hex)[:4]. The hub's
// AppPubkey is published in the clear as the "p" tag of the hub's own kind-13194
// NIP-47 info event (lokihub nip47/publish_nip47_info.go:93), a REPLACEABLE event
// relays keep indefinitely. So the preimage set is harvestable, and an observer who
// sees a token can attribute it to a NAMED hub, not merely group it.
//
// This measures the two things that matter: the derivation is a plain unsalted hash
// of a value published on the relay, and 4 bytes is wide enough to be unique across
// any realistic candidate set.
func TestAuditBPriv_HubGroupIsAReversibleLookup(t *testing.T) {
	const n = 200000

	table := make(map[string]string, n)
	collisions := 0
	var sample string
	for i := 0; i < n; i++ {
		var buf [32]byte
		if _, err := rand.Read(buf[:]); err != nil {
			t.Fatal(err)
		}
		appPubkey := hex.EncodeToString(buf[:]) // exactly what a 13194 "p" tag carries
		fp := hex.EncodeToString(HubGroupFor(appPubkey))
		if _, dup := table[fp]; dup {
			collisions++
		}
		table[fp] = appPubkey
		if i == 0 {
			sample = appPubkey
		}
	}

	// The attack, end to end: a token's TLV-7 value looked up in the harvested table
	// yields the issuing hub's AppPubkey.
	want := sample
	got := table[hex.EncodeToString(HubGroupFor(want))]
	if got != want {
		t.Fatalf("lookup failed: got %s want %s", got, want)
	}
	t.Logf("HubGroupLen=%d bytes (%d bits)", HubGroupLen, HubGroupLen*8)
	t.Logf("%d candidate hub pubkeys -> %d distinct fingerprints, %d collisions (%.4f%%)",
		n, len(table), collisions, 100*float64(collisions)/float64(n))
	t.Logf("reverse lookup of a token's TLV-7 recovered the exact issuing AppPubkey")

	// Cost of building the table for a plausible relay-wide hub population.
	for _, hubs := range []int{100, 10000, 1000000} {
		// birthday approximation: hubs^2 / (2 * 2^32)
		exp := float64(hubs) * float64(hubs) / (2 * 4294967296)
		t.Logf("  %8d hubs -> ~%.4f expected fingerprint collisions", hubs, exp)
	}
}

// The fingerprint is an unkeyed hash of a single 64-char hex string, so it is also
// brute-forceable without any harvesting at all IF the observer can guess candidate
// pubkeys — but more importantly it is deterministic, so two tokens minted by one hub
// always carry the identical 4 bytes.
func TestAuditBPriv_HubGroupClustersBillsDeterministically(t *testing.T) {
	hub := "11" + "00000000000000000000000000000000000000000000000000000000000000"
	a := HubGroupFor(hub)
	b := HubGroupFor(hub)
	if hex.EncodeToString(a) != hex.EncodeToString(b) {
		t.Fatal("not deterministic")
	}
	other := "22" + "00000000000000000000000000000000000000000000000000000000000000"
	if hex.EncodeToString(HubGroupFor(other)) == hex.EncodeToString(a) {
		t.Fatal("unexpected collision in fixture")
	}
	t.Logf("hub A fingerprint %s; hub B fingerprint %s — every bill a hub mints carries the same 4 bytes",
		hex.EncodeToString(a), hex.EncodeToString(HubGroupFor(other)))
}
