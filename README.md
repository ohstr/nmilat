# nmilat

[![CI](https://github.com/ohstr/nmilat/actions/workflows/ci.yml/badge.svg)](https://github.com/ohstr/nmilat/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ohstr/nmilat.svg)](https://pkg.go.dev/github.com/ohstr/nmilat)
[![Go Report Card](https://goreportcard.com/badge/github.com/ohstr/nmilat)](https://goreportcard.com/report/github.com/ohstr/nmilat)
![Go Version](https://img.shields.io/github/go-mod/go-version/ohstr/nmilat)
[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](LICENSE)
![Go](https://img.shields.io/badge/Go-%2300ADD8.svg?style=flat&logo=go&logoColor=white)

nmilat is a Go SDK for building on the Nostr protocol. It handles the plumbing —
event parsing, signing, verification, and 32 NIPs — so you can focus on what
you're building.

Use it to:

- **Build a client or bot** that reads, signs, and publishes Nostr events
- **Run your own relay** with the embeddable engine: event storage, sessions,
  and profile search included
- **Talk to remote relays** over WebSocket without hand-rolling the wire protocol

No CLI or UI code lives here — this module is a library only. The
[`ncli`](https://github.com/ohstr/ncli) application is built on top of it.

## Install

```sh
go get github.com/ohstr/nmilat
```

## Package overview

### Implemented NIPs

- **[`nip01`](https://github.com/nostr-protocol/nips/blob/master/01.md)** — Core event, filter, and subscription types (the foundation every other package builds on)
- **[`nip04`](https://github.com/nostr-protocol/nips/blob/master/04.md), [`nip44`](https://github.com/nostr-protocol/nips/blob/master/44.md), [`nip49`](https://github.com/nostr-protocol/nips/blob/master/49.md)** — Encryption: direct messages, payloads, private keys
- **[`nip05`](https://github.com/nostr-protocol/nips/blob/master/05.md)** — NIP-05 identity verification
- **[`nip09`](https://github.com/nostr-protocol/nips/blob/master/09.md)** — Event deletion
- **[`nip11`](https://github.com/nostr-protocol/nips/blob/master/11.md)** — Relay information document
- **[`nip13`](https://github.com/nostr-protocol/nips/blob/master/13.md)** — Proof of work
- **[`nip16`](https://github.com/nostr-protocol/nips/blob/master/16.md)** — Event treatment (regular/replaceable/ephemeral kinds)
- **[`nip17`](https://github.com/nostr-protocol/nips/blob/master/17.md), [`nip59`](https://github.com/nostr-protocol/nips/blob/master/59.md)** — Private direct messages, gift wraps
- **[`nip19`](https://github.com/nostr-protocol/nips/blob/master/19.md)** — Bech32-encoded entities: npub, nsec, note, plus the TLV-based nprofile, nevent, and naddr
- **[`nip23`](https://github.com/nostr-protocol/nips/blob/master/23.md)** — Long-form content
- **[`nip26`](https://github.com/nostr-protocol/nips/blob/master/26.md)** — Event delegation
- **[`nip33`](https://github.com/nostr-protocol/nips/blob/master/33.md)** — Parameterized replaceable events (now called addressable events)
- **[`nip40`](https://github.com/nostr-protocol/nips/blob/master/40.md)** — Event expiration
- **[`nip42`](https://github.com/nostr-protocol/nips/blob/master/42.md), [`nip98`](https://github.com/nostr-protocol/nips/blob/master/98.md)** — Relay/HTTP authentication
- **[`nip43`](https://github.com/nostr-protocol/nips/blob/master/43.md)** — Relay access metadata and requests
- **[`nip46`](https://github.com/nostr-protocol/nips/blob/master/46.md)** — Nostr Connect (remote signing)
- **[`nip47`](https://github.com/nostr-protocol/nips/blob/master/47.md)** — Wallet Connect (NWC): info/request/response/notification events, encryption negotiation, pairing URI
- **[`nip48`](https://github.com/nostr-protocol/nips/blob/master/48.md)** — Proxy tags
- **[`nip57`](https://github.com/nostr-protocol/nips/blob/master/57.md)** — Lightning zaps
- **[`nip65`](https://github.com/nostr-protocol/nips/blob/master/65.md)** — Relay list metadata
- **[`nip77`](https://github.com/nostr-protocol/nips/blob/master/77.md)** — Negentropy sync
- **[`nip88`](https://github.com/nostr-protocol/nips/blob/master/88.md)** — Polls
- **[`nip90`](https://github.com/nostr-protocol/nips/blob/master/90.md)** — Data Vending Machines
- **[`nipAA`](https://github.com/block/buzz/blob/main/docs/nips/NIP-AA.md)** — Agent Auth
- **[`nipAZ`](https://github.com/ohstr/zapf-nips/blob/main/NIP-AZ.md)** — AltZap: zaps for energy-backed coins
- **[`nipB0`](https://github.com/nostr-protocol/nips/blob/master/B0.md)** — Web bookmarks
- **[`nipB7`](https://github.com/nostr-protocol/nips/blob/master/B7.md)** — Blossom media
- **[`nipcash`](https://github.com/flokiorg/lokihub/blob/main/docs/nips/NIP-CASH.md)** — Cash Hub: ecash system
- **[`nipcw`](https://github.com/flokiorg/lokihub/blob/main/docs/nips/NIP-CW.md)** — Circle Wallet: shared self-service wallets
- **[`nipIC`](https://github.com/ohstr/zapf-nips/blob/main/NIP-IC.md)** — Identity Connection: binds Web Identity accounts to Nostr pubkeys
- **[`nipOA`](https://github.com/block/buzz/blob/main/docs/nips/NIP-OA.md)** — Owner Attestation

### Relay engine and infrastructure

- **`relay`** — Embeddable relay engine
- **`relay/client`** — Relay client (WebSocket, NWC)
- **`relay/migrations`** — Event store schema migrations
- **`search`** — Profile search indexing/ranking
- **`config`** — Embedded YAML config for search
- **`wire`** — Relay wire-protocol packet types
- **`utils`** — Shared event/key/logging helpers

NIP packages with relay-side concerns (NIP-47/48/57/65/88/90/B0/B7) stay
dependency-free on their own; blank-import their `relayreg` subpackage to
declare relay support, e.g. `import _ "github.com/ohstr/nmilat/nip57/relayreg"`.
See "Run a relay" below.

## Quick start

### Run a relay

```go
package main

import (
	"log"
	"net/http"

	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/relay"

	// Blank-import the relayreg subpackage for every optional NIP this relay
	// should declare support for and auto-validate incoming events against.
	// Without these, relay.New still works — it just won't know about
	// zaps/polls/DVMs/etc. NIP-09/16/33/40/77 are always on (core to NIP-01
	// handling), and NIP-42/43/AA/26/50 turn on automatically from
	// SessionConfig — none of those need a relayreg import.
	_ "github.com/ohstr/nmilat/nip57/relayreg"
	_ "github.com/ohstr/nmilat/nip65/relayreg"
)

func main() {
	metadata := &nip11.Metadata{
		Name:       "my-relay",
		Limitation: nip11.Limitation{MaxLimit: 1000, MaxMessageLength: 1024 * 1024},
	}

	rl, err := relay.New("relay.db", metadata)
	if err != nil {
		log.Fatal(err)
	}
	defer rl.Close()

	log.Fatal(http.ListenAndServe(":8080", rl))
}
```

`relay.New` includes NIP-11 relay-info negotiation and starts profile
verification, with search disabled. For storage tuning, a search service, or
session options (CORS allowlist, NIP-26 delegation, ...), build the store
and handler directly with `relay.NewEventStore`/`relay.NewSessionHandler`
instead.

Connect with `relayclient.Connect` against `ws://localhost:8080` (next example).

### Read events from a relay

Connect, subscribe to a filter, and read events until EOSE. Relay input is untrusted,
so always call `Verify()` before acting on an event:

```go
package main

import (
	"context"
	"fmt"
	"net/url"

	"github.com/ohstr/nmilat/nip01"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

func main() {
	filters := nip01.NewSubscriptionFilterGroup(nip01.NewFilter().WithKinds(1).WithLimit(10))

	relayURL, _ := url.Parse("wss://relay.ohstr.com")
	events, err := relayclient.ReadEventsFromRelay(context.Background(), relayURL, filters)
	if err != nil {
		panic(err)
	}
	for _, ev := range events {
		if err := ev.Verify(); err != nil {
			continue // bad signature, bad ID, or malformed — skip it
		}
		fmt.Println(ev.ID, ev.Content)
	}
}
```

### Build, sign, and publish an event

Create an event, sign it with your private key, and publish it to a relay:

```go
package main

import (
	"context"
	"fmt"
	"net/url"

	"github.com/ohstr/nmilat/nip01"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

func main() {
	// privateKeyHex is your hex-encoded Nostr private key — see
	// "Encode & decode keys" below for converting to/from npub/nsec.
	ev, err := nip01.NewSignedEvent(1, "hello nostr", privateKeyHex)
	if err != nil {
		panic(err)
	}

	relayURL, _ := url.Parse("wss://relay.ohstr.com")
	conn, err := relayclient.Connect(context.Background(), relayURL)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	res, err := conn.Publish(context.Background(), ev)
	if err != nil {
		panic(err)
	}
	fmt.Println("accepted:", res.Accepted, res.Message)
}
```

### Send a private direct message (NIP-17/59)

Build a chat message, seal and gift-wrap it so only the recipient can read it
(sender identity included), and publish the wrapper like any other event:

```go
package main

import (
	"context"
	"fmt"
	"net/url"

	"github.com/ohstr/nmilat/nip17"
	"github.com/ohstr/nmilat/nip59"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

func main() {
	rumor := nip17.NewChatMessage("gm from nmilat")
	if err := rumor.Sign(senderPrivKeyHex); err != nil {
		panic(err)
	}

	// Wrap encrypts the rumor twice (seal, then gift wrap) so relays and
	// onlookers see only an anonymous kind-1059 event addressed to recipientPubKeyHex.
	giftWrap, err := nip59.Wrap(rumor, senderPrivKeyHex, recipientPubKeyHex)
	if err != nil {
		panic(err)
	}

	relayURL, _ := url.Parse("wss://relay.ohstr.com")
	conn, err := relayclient.Connect(context.Background(), relayURL)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	res, err := conn.Publish(context.Background(), giftWrap)
	if err != nil {
		panic(err)
	}
	fmt.Println("delivered:", res.Accepted, res.Message)
}
```

### Send a zap request (NIP-57)

`nip57` implements the spec-compliant kind 9734/9735 zap request/receipt/LNURL
flow:

```go
package main

import (
	"context"
	"fmt"
	"net/url"

	"github.com/ohstr/nmilat/nip57"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

func main() {
	zapRequest := nip57.NewZapRequest(nip57.ZapRequestParams{
		Recipient:  recipientPubKeyHex,
		Lnurl:      recipientLnurl,
		AmountMsat: 21000,
		Relays:     []string{"wss://relay.ohstr.com"},
	})
	if err := zapRequest.Sign(senderPrivKeyHex); err != nil {
		panic(err)
	}

	relayURL, _ := url.Parse("wss://relay.ohstr.com")
	conn, err := relayclient.Connect(context.Background(), relayURL)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	res, err := conn.Publish(context.Background(), zapRequest)
	if err != nil {
		panic(err)
	}
	fmt.Println("zap request accepted:", res.Accepted, res.Message)
}
```

### Send an AltZap request to a Web Identity recipient (NIP-AZ + NIP-IC)

**AltZap** is the same flow for non-Bitcoin chains — a mandatory `chain` tag
and its own kinds (5520-5523). Its most common use isn't zapping a native
Nostr pubkey (`nipAZ.Pubkey(hex)`) — it's zapping a recipient who only has an
account on another platform and no Nostr keypair yet. `nipAZ.Connection`
covers that case by deriving a **NIP-IC** `ConnectionKey` internally:

```go
package main

import (
	"context"
	"fmt"
	"net/url"

	"github.com/ohstr/nmilat/nipAZ"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

func main() {
	zapRequest, err := nipAZ.NewAltZapRequest(nipAZ.AltZapRequestParams{
		PrivateKey: senderPrivKeyHex, // signs internally
		Chain:      "flokicoin",      // prevents cross-chain replay
		// Recipient has no Nostr pubkey yet — identified by their Discord
		// account instead. nipAZ.Connection hashes platform+externalID into
		// a nipIC.ConnectionKey; use nipAZ.Pubkey(hex) for a native Nostr
		// recipient instead.
		Recipient:   nipAZ.Connection("discord", externalUserID),
		Lnurl:       recipientLnurl,
		AmountMloki: 21000,
		Relays:      []string{"wss://relay.ohstr.com"},
	})
	if err != nil {
		panic(err)
	}

	relayURL, _ := url.Parse("wss://relay.ohstr.com")
	conn, err := relayclient.Connect(context.Background(), relayURL)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	res, err := conn.Publish(context.Background(), zapRequest)
	if err != nil {
		panic(err)
	}
	fmt.Println("zap request accepted:", res.Accepted, res.Message)
}
```

### Bind a Web Identity to a Nostr pubkey (NIP-IC)

**nipIC** implements Identity Connection: an Identity Authority (IA) attests
that a Web Identity account (Discord, Telegram, ...) belongs to a Nostr
pubkey by signing a Kind 35522 event; the user then references it from their
own Kind 35521.

```go
package main

import (
	"fmt"

	"github.com/ohstr/nmilat/nipIC"
)

func main() {
	// 1. Mint a challenge + pre-auth code for the user to prove control of
	//    their Nostr key, e.g. by posting the pre-auth code publicly.
	challenge, preAuthCode, err := nipIC.NewChallenge(userPubkeyHex)
	if err != nil {
		panic(err)
	}

	// 2. Once the IA has verified the public post, it signs the attestation.
	connectionKey := nipIC.NewConnectionKey("discord", externalUserID)
	attestation, err := nipIC.NewAttestation(nipIC.AttestationParams{
		PrivateKey:     iaPrivKeyHex, // IA's nsec hex, signs internally
		ConnectionKey:  connectionKey,
		UserPubkey:     userPubkeyHex,
		Platform:       "discord",
		ExpirationDays: 90,
		Evidence: nipIC.Evidence{
			Platform:    "discord",
			UserID:      externalUserID,
			Username:    "alice",
			EvidenceURL: "https://discord.com/channels/.../123456789",
			Challenge:   challenge,
			PreAuthCode: preAuthCode,
		},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("attestation id:", attestation.ID)
}
```

A verifier re-checks cross-IA re-attestation evidence with
`challenge.Verify(userPubkeyHex, preAuthCode)` before trusting it — see
[NIP-IC's Cross-IA Challenge Binding](https://github.com/ohstr/zapf-nips/blob/main/references/identity-connection.md#e--cross-ia-challenge-binding)
for the full security model.

### Pay an invoice over Nostr Wallet Connect (NIP-47)

Parse a `nostr+walletconnect://` pairing URI and construct a `NWCClient` —
it dials the wallet's relay once and keeps the connection open for reuse
across calls. `PayInvoice` and the other wallet operations are plain
methods: no type parameter at the call site, and a wallet-side decline comes
back as a `*relayclient.WalletError` you can `errors.As` for the code and
message:

```go
package main

import (
	"context"
	"fmt"

	"github.com/ohstr/nmilat/nip47"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

func main() {
	// pairingURI is the nostr+walletconnect:// string the user's wallet gave
	// you; it carries the wallet's pubkey, relay(s), and your app's secret key.
	pairing, err := nip47.ParsePairingURI(pairingURI)
	if err != nil {
		panic(err)
	}

	wallet, err := relayclient.NewNWCClient(context.Background(), pairing, nip47.EncryptionNIP44V2)
	if err != nil {
		panic(err)
	}
	defer wallet.Close()

	result, err := wallet.PayInvoice(context.Background(), nip47.PayInvoiceParams{
		Invoice: "lnfcxxxx....", // lnbcxxx for bitcoin
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("paid! preimage:", result.Preimage)
}
```

### Mint cash and redeem it into a Circle Wallet (NIP-CASH + NIP-CW)

**NIP-CASH** mints `lokicash1...`/`satscash1...` bech32 tokens that carry
real, spendable value the moment they're minted — hand one to someone the
way you'd hand over a bill. **NIP-CW** self-serves a personal wallet from a
host's own node, for people who don't want to run one themselves. The two
compose naturally: a Circle Wallet member redeeming a cash token straight
into their own wallet, on the *same host* that minted the cash, is the one
case where `cash_redeem`'s same-node fee exemption applies deterministically
— always the full amount, zero fee, since nothing leaves the node. Both
packages follow the protocol/client split every other NIP here does
(`nipcash` builds/parses, `nipcash/client` dials out) — imported under an
alias here since both are used together in the same file:

```go
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/ohstr/nmilat/nip47"
	"github.com/ohstr/nmilat/nipcash"
	cashclient "github.com/ohstr/nmilat/nipcash/client"
	"github.com/ohstr/nmilat/nipcw"
	cwclient "github.com/ohstr/nmilat/nipcw/client"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

func main() {
	ctx := context.Background()

	// Mint a slice for a Nostr-identified recipient, over the Cash Hub's
	// own connection.
	hub, err := cashclient.Connect(ctx, cashHubPairingURI)
	if err != nil {
		panic(err)
	}
	defer hub.Close()

	minted, err := hub.MintCash(ctx, nipcash.MintCashParams{
		Recipients: []nipcash.Allocation{nipcash.Send(nipcash.Pubkey(memberPubkeyHex), 21_000_000)},
		Expiry:     24 * time.Hour,
	})
	if err != nil {
		panic(err)
	}

	// The member self-serves their own Circle Wallet from the host's Hub.
	circleHub, err := cwclient.Connect(ctx, circleHubPairingURI)
	if err != nil {
		panic(err)
	}
	defer circleHub.Close()

	wallet, err := circleHub.CreateCircleWallet(ctx, nipcw.CreateCircleWalletParams{
		Credential:      nipcw.BySigning(memberPrivKeyHex),
		MaxAmountMillis: 100_000_000,
	})
	if err != nil {
		panic(err)
	}

	// Invoice from their own Circle Wallet — same host as the Cash Hub, so
	// this redemption always resolves same-node: full amount, zero fee.
	memberPairing, err := nip47.ParsePairingURI(wallet.PairingURI)
	if err != nil {
		panic(err)
	}
	member, err := relayclient.NewNWCClient(ctx, memberPairing, nip47.EncryptionNIP44V2)
	if err != nil {
		panic(err)
	}
	defer member.Close()

	invoice, err := member.MakeInvoice(ctx, nip47.MakeInvoiceParams{Amount: 21_000_000})
	if err != nil {
		panic(err)
	}

	cashWallet, err := cashclient.Connect(ctx, minted.CashToken)
	if err != nil {
		panic(err)
	}
	defer cashWallet.Close()

	result, err := cashWallet.CashRedeem(ctx, nipcash.CashRedeemParams{
		Invoice:    invoice.Invoice,
		Credential: nipcash.BySigning(memberPrivKeyHex),
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("redeemed! preimage:", result.Preimage, "fees paid:", result.FeesPaid)
}
```

### Upload a blob to a Blossom server (NIP-B7)

Build a BUD-11 Authorization token scoped to the `upload` verb, then hand it
to `nipB7/client` to stream the blob to a server and get back its Blob
Descriptor:

```go
package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nipB7"
	blossom "github.com/ohstr/nmilat/nipB7/client"
)

func main() {
	auth := nipB7.NewAuthorization(nipB7.AuthorizationParams{
		Verb:       nipB7.VerbUpload,
		Content:    "Upload blob",
		Expiration: time.Now().Add(5 * time.Minute),
	})
	if err := auth.Sign(privateKeyHex); err != nil {
		panic(err)
	}

	c := &blossom.Client{}
	descriptor, err := c.Upload(context.Background(), "https://blossom.example", blossom.UploadRequest{
		Body:        strings.NewReader("hello nostr"),
		Size:        11,
		ContentType: "text/plain",
		Auth:        auth,
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("stored at:", descriptor.URL)
}
```

`c.Get`/`c.GetFromServers` download the same way (streamed, with
server-list fallback), and `nipB7.VerifyAuthorization` is the server-side,
BUD-11 analogue of NIP-98's `VerifyAuthHeader`.

### Encode & decode entities (NIP-19)

Convert between raw hex keys/IDs and Nostr's bech32 encoding (`npub`/`nsec`/`note`):

```go
import "github.com/ohstr/nmilat/nip19"

npub, err := nip19.EncodePublicKey(pubkeyHex)
if err != nil {
	panic(err)
}
fmt.Println(npub) // npub1...

decoded, err := nip19.DecodePublicKey(npub)
if err != nil {
	panic(err)
}
fmt.Println(decoded) // pubkeyHex
```

`DecodePublicKey`/`DecodePrivateKey`/`DecodeNote` are typed wrappers; the
generic `nip19.Decode` is also available for callers that need to handle an
identifier of unknown/mixed type.

The TLV-based "shareable identifiers with extra metadata" — `nprofile`,
`nevent`, and `naddr` — carry a public key/event ID plus optional relay
hints (and, for `nevent`/`naddr`, an optional author and kind):

```go
nprofile, err := nip19.EncodeProfile(pubkeyHex, []string{"wss://relay.example.com"})
profile, err := nip19.DecodeProfile(nprofile) // *nip19.ProfilePointer{PublicKey, Relays}

nevent, err := nip19.EncodeEvent(nip19.EventPointer{
	ID:     eventIDHex,
	Relays: []string{"wss://relay.example.com"},
	Author: pubkeyHex, // optional
	Kind:   1,         // optional
})
event, err := nip19.DecodeEvent(nevent) // *nip19.EventPointer

naddr, err := nip19.EncodeAddr(nip19.EntityPointer{
	Identifier: "my-article",
	PublicKey:  pubkeyHex,
	Kind:       30023,
	Relays:     []string{"wss://relay.example.com"},
})
addr, err := nip19.DecodeAddr(naddr) // *nip19.EntityPointer
```

## Development

Uses [`just`](https://github.com/casey/just) for build automation:

```sh
just build   # compile-check (library, no binary)
just test    # go test ./...
just vet     # go vet ./...
just tidy    # go mod tidy
just check   # build + vet + test
```

## License

[Unlicense](LICENSE) — public domain.
