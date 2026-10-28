package listing

import (
	"encoding/hex"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipCO"
	"github.com/ohstr/nmilat/nipcash"
	"github.com/ohstr/nmilat/nipcw"
)

const (
	key1 = "0000000000000000000000000000000000000000000000000000000000000001"
	key2 = "0000000000000000000000000000000000000000000000000000000000000002"
	key3 = "0000000000000000000000000000000000000000000000000000000000000003"
	key4 = "0000000000000000000000000000000000000000000000000000000000000004"

	node     = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	pub2     = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
	pub4     = "e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13"
	kcoConn  = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
	relayURL = "wss://relay.example.com"
	addr1    = "31190:" + node + ":" + kcoConn

	kList1ID = "a2aeaaa40b57de5807c1a466060e58111c23eaa96390a0b894982bcafbe555b0"
	kList2ID = "25d3a99b0b593aa70ad5d848a91cd300062f6c4a479bc7005d66277897a96506"
	kLDel1   = "5aa2a615eb258246769d21389dee11481066e3ef3809e9a25a7847acd848d37b"
	kOps1    = "3b74fc1d53fa35a72ba235ce398dc29e599f19e202fc5c16bec156179e1480a0"
	kRec1    = "1ffb32f70209a551300255197aad28472ef74130e432011039d6b5da5d45a5f8"
	kRep1    = "00cc61c6f4914fac8dfc65a4a29057f687f4af1be394213658e7d53d5e1c1abd"

	createdList1 = 1792713600
	expList1     = 1795305600
)

func signWith(priv string) func(*nip01.Event) error {
	return func(ev *nip01.Event) error { return ev.Sign(priv) }
}

func connSecret() string {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(0x40 + i)
	}
	return hex.EncodeToString(b)
}

// kco1 is the K-CO-1 Order connection (NIP-CO's example), signed by key 1.
func kco1(t testing.TB) *nipCO.OrderConnection {
	t.Helper()
	sign, err := nipcash.LocalChainSigner(key1, "bitcoin")
	if err != nil {
		t.Fatal(err)
	}
	c, err := nipCO.SignOrderConnection(nipCO.OrderConnection{Pubkey: kcoConn, Relays: []string{relayURL},
		Secret: connSecret(), Label: "Alice's cash counter", HasLabel: true, HubIdentity: node, Chain: "bitcoin"}, sign, node)
	if err != nil {
		t.Fatal(err)
	}
	return &c
}

// circleConn is a Circle Wallet Hub connection of node (key 1) with pubkey conn.
func circleConn(t testing.TB, conn string) *nipcw.CircleHubConnection {
	t.Helper()
	sign, err := nipcash.LocalChainSigner(key1, "bitcoin")
	if err != nil {
		t.Fatal(err)
	}
	c, err := nipcw.SignCircleHubConnection(nipcw.CircleHubConnection{Pubkey: conn, Relays: []string{relayURL},
		Secret: connSecret(), HubIdentity: node, Chain: "bitcoin"}, sign, node)
	if err != nil {
		t.Fatal(err)
	}
	return &c
}

// kList1Fields are the NIP example's fields with K-CO-1 and operator key 2.
func kList1Fields(t testing.TB) ListingFields {
	return ListingFields{
		Order:      kco1(t),
		Network:    "mainnet",
		Summary:    []string{"lightning", "onchain"},
		Title:      "Alice's cash counter",
		Image:      "https://example.com/counter.png",
		Content:    "Cash for the Lisbon meetup. Lightning or on-chain, paid out within the hour.",
		Location:   "Lisbon, Baixa",
		Operator:   &Ref{Pubkey: pub2, Relay: relayURL},
		Status:     StatusOpen,
		Expiration: expList1,
		Hints:      []Hint{{Payment: "lightning", MinMillis: 1000000, MaxMillis: 1000000000, FeeBase: 1000, FeePpm: 1000}},
		Languages:  []string{"pt", "en"},
		Geohashes:  []string{"eyc"},
	}
}

func kList1Event(t testing.TB) *nip01.Event {
	t.Helper()
	ev, err := NewListing(kList1Fields(t), createdList1, createdList1, signWith(key1))
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

var mainnet = CheckOptions{Chains: []string{"bitcoin"}}

func kList1(t testing.TB) *Listing {
	t.Helper()
	l, err := ParseListing(kList1Event(t), mainnet)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// resign returns a copy of ev with tags edited by f, signed again by priv.
func resign(t testing.TB, ev *nip01.Event, priv string, f func(e *nip01.Event)) *nip01.Event {
	t.Helper()
	c := ev.Copy()
	f(c)
	if err := c.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return c
}

func setTag(ev *nip01.Event, name, value string) {
	for _, tg := range ev.Tags {
		if len(tg) >= 2 && tg[0] == name {
			tg[1] = value
			return
		}
	}
	ev.Tags = append(ev.Tags, []string{name, value})
}

func dropTag(ev *nip01.Event, name string) {
	var out [][]string
	for _, tg := range ev.Tags {
		if len(tg) == 0 || tg[0] != name {
			out = append(out, tg)
		}
	}
	ev.Tags = out
}
