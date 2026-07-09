// Package nip47 implements NIP-47: Nostr Wallet Connect (NWC), a protocol
// letting Nostr clients access a remote Lightning wallet service over
// end-to-end encrypted Nostr events, using a unique keypair per connection.
//
// This package is the protocol layer only: building/parsing the info,
// request, response, and notification events, encryption negotiation
// (NIP-04 legacy vs NIP-44), the standard command set, and the
// nostr+walletconnect:// pairing URI. It has no opinion on how a wallet
// service persists connections, enforces budgets, or talks to a Lightning
// backend — that belongs to the consumer (e.g. a wallet-service
// application) built on top of this package.
package nip47

// Event kinds defined by NIP-47.
const (
	KindNWCInfo               = 13194 // wallet service capability advertisement
	KindNWCRequest            = 23194 // client -> wallet service command
	KindNWCResponse           = 23195 // wallet service -> client result
	KindNWCLegacyNotification = 23196 // wallet service -> client event alert, NIP-04 encrypted
	KindNWCNotification       = 23197 // wallet service -> client event alert, NIP-44 encrypted
)

// Encryption scheme identifiers used in the info event's "encryption" tag
// and the request event's "encryption" tag.
const (
	EncryptionNIP04   = "nip04"
	EncryptionNIP44V2 = "nip44_v2"
)
