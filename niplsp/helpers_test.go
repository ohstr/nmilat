package niplsp

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/flokiorg/go-flokicoin/crypto/schnorr"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/utils"
)

// Key 1: the NIP-LSP example's node key.
const (
	key1Priv = "0000000000000000000000000000000000000000000000000000000000000001"
	key1Pub  = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	key2Pub  = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"

	exampleCreatedAt  = 1792713600
	exampleExpiration = 1795305600
	exampleID         = "d87841c795e01ba75208a603bc0bdfe7f2015ab3876860501e2f09d0c257a45b"
)

// exampleFields are the inputs of K-LSP-1, the NIP-LSP example.
func exampleFields() Fields {
	return Fields{
		Meta: Meta{
			NodeKey: key1Pub,
			Addrs: []string{
				"vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:9735",
				"203.0.113.7:9735",
			},
			Chain:      "bitcoin",
			Network:    "mainnet",
			Status:     StatusOpen,
			Expiration: exampleExpiration,
			Display: Display{
				Title:     "Alice's Liquidity",
				Content:   "Inbound channels and just-in-time channels.",
				Website:   "https://lsp.example.com",
				Operator:  &Operator{Pubkey: key2Pub, Relay: "wss://relay.example.com"},
				Languages: []string{"en"},
			},
			Relays: []string{"wss://relay.example.com"},
		},
		Protocols: []int{1, 2, 5},
		LSPS1: []Option{
			{"min_required_channel_confirmations", "0"},
			{"min_funding_confirms_within_blocks", "6"},
			{"supports_zero_channel_reserve", "false"},
			{"max_channel_expiry_blocks", "12960"},
			{"min_initial_client_balance", "0"},
			{"max_initial_client_balance", "1000000"},
			{"min_initial_lsp_balance", "0"},
			{"max_initial_lsp_balance", "10000000"},
			{"min_channel_balance", "100000"},
			{"max_channel_balance", "10000000"},
		},
		LSPS2: []FeeRow{{2000000, 4000, 4320, 2016, 10000000, 4000000000}},
		LSPS5: []Option{{"max_webhooks", "10"}},
	}
}

// exampleTags are the NIP-LSP example's tags, verbatim.
var exampleTags = [][]string{
	{"addr", "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:9735"},
	{"addr", "203.0.113.7:9735"},
	{"n", "bitcoin"},
	{"network", "mainnet"},
	{"status", "open"},
	{"expiration", "1795305600"},
	{"protocol", "1"},
	{"protocol", "2"},
	{"protocol", "5"},
	{"lsps1", "min_required_channel_confirmations", "0"},
	{"lsps1", "min_funding_confirms_within_blocks", "6"},
	{"lsps1", "supports_zero_channel_reserve", "false"},
	{"lsps1", "max_channel_expiry_blocks", "12960"},
	{"lsps1", "min_initial_client_balance", "0"},
	{"lsps1", "max_initial_client_balance", "1000000"},
	{"lsps1", "min_initial_lsp_balance", "0"},
	{"lsps1", "max_initial_lsp_balance", "10000000"},
	{"lsps1", "min_channel_balance", "100000"},
	{"lsps1", "max_channel_balance", "10000000"},
	{"lsps2_fee", "2000000", "4000", "4320", "2016", "10000000", "4000000000"},
	{"lsps5", "max_webhooks", "10"},
	{"title", "Alice's Liquidity"},
	{"website", "https://lsp.example.com"},
	{"p", "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5", "wss://relay.example.com"},
	{"L", "ISO-639-1"},
	{"l", "en", "ISO-639-1"},
	{"alt", "Lightning service provider: Alice's Liquidity"},
	{"r", "wss://relay.example.com"},
}

// localSigner is a NodeSigner over a private key, as a node's Schnorr RPC
// behaves: it hashes the payload itself.
func localSigner(t testing.TB, privHex string) NodeSigner {
	t.Helper()
	priv, err := utils.ParsePrivateKeyHex(privHex)
	if err != nil {
		t.Fatal(err)
	}
	return func(_ context.Context, payload []byte) ([]byte, error) {
		h := sha256.Sum256(payload)
		sig, err := schnorr.Sign(priv, h[:])
		if err != nil {
			return nil, err
		}
		return sig.Serialize(), nil
	}
}

// signed builds and signs an announcement with key 1.
func signed(t testing.TB, f Fields, createdAt int64) *nip01.Event {
	t.Helper()
	ev, err := NewAnnouncement(f, createdAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := Sign(context.Background(), ev, localSigner(t, key1Priv)); err != nil {
		t.Fatal(err)
	}
	return ev
}

// signRaw signs an event with arbitrary tags by key 1, bypassing the builder.
func signRaw(t testing.TB, kind int, createdAt int64, content string, tags [][]string) *nip01.Event {
	t.Helper()
	ev := nip01.NewUnsignedEvent(kind, key1Pub, content, tags...)
	ev.CreatedAt = uint64(createdAt)
	if err := ev.Sign(key1Priv); err != nil {
		t.Fatal(err)
	}
	return ev
}

func cloneTags(tags [][]string) [][]string {
	out := make([][]string, len(tags))
	for i, t := range tags {
		out[i] = append([]string(nil), t...)
	}
	return out
}

// findTag is the first tag named name, whole, or nil.
func findTag(ev *nip01.Event, name string) []string {
	for _, tag := range ev.Tags {
		if len(tag) > 0 && tag[0] == name {
			return tag
		}
	}
	return nil
}
