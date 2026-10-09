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
- **[`nip22`](https://github.com/nostr-protocol/nips/blob/master/22.md)** — Comment: generic kind:1111 threading note
- **[`nip23`](https://github.com/nostr-protocol/nips/blob/master/23.md)** — Long-form content
- **[`nip26`](https://github.com/nostr-protocol/nips/blob/master/26.md)** — Event delegation
- **[`nip29`](https://github.com/nostr-protocol/nips/blob/master/29.md)** — Relay-based groups: moderation events, join/leave requests, relay-authored group metadata
- **[`nip33`](https://github.com/nostr-protocol/nips/blob/master/33.md)** — Parameterized replaceable events (now called addressable events)
- **[`nip34`](https://github.com/nostr-protocol/nips/blob/master/34.md)** — git stuff: code collaboration over Nostr
- **[`nip40`](https://github.com/nostr-protocol/nips/blob/master/40.md)** — Event expiration
- **[`nip42`](https://github.com/nostr-protocol/nips/blob/master/42.md), [`nip98`](https://github.com/nostr-protocol/nips/blob/master/98.md)** — Relay/HTTP authentication
- **[`nip43`](https://github.com/nostr-protocol/nips/blob/master/43.md)** — Relay access metadata and requests
- **[`nip46`](https://github.com/nostr-protocol/nips/blob/master/46.md)** — Nostr Connect (remote signing)
- **[`nip47`](https://github.com/nostr-protocol/nips/blob/master/47.md)** — Wallet Connect (NWC): info/request/response/notification events, encryption negotiation, pairing URI
- **[`nip48`](https://github.com/nostr-protocol/nips/blob/master/48.md)** — Proxy tags
- **[`nip53`](https://github.com/nostr-protocol/nips/blob/master/53.md)** — Live streaming and spaces: live streams, meeting spaces and their rooms, listener presence, live chat
- **[`nip57`](https://github.com/nostr-protocol/nips/blob/master/57.md)** — Lightning zaps
- **[`nip65`](https://github.com/nostr-protocol/nips/blob/master/65.md)** — Relay list metadata
- **[`nip70`](https://github.com/nostr-protocol/nips/blob/master/70.md)** — Protected events: the `-` tag, accepted only from their authenticated author
- **[`nip71`](https://github.com/nostr-protocol/nips/blob/master/71.md)** — Video events: normal, short and addressable videos with imeta variants
- **[`nip77`](https://github.com/nostr-protocol/nips/blob/master/77.md)** — Negentropy sync
- **[`nip86`](https://github.com/nostr-protocol/nips/blob/master/86.md)** — Relay Management API: NIP-98-authenticated JSON-RPC to administer a relay over HTTP
- **[`nip88`](https://github.com/nostr-protocol/nips/blob/master/88.md)** — Polls
- **[`nip90`](https://github.com/nostr-protocol/nips/blob/master/90.md)** — Data Vending Machines
- **[`nipA0`](https://github.com/nostr-protocol/nips/blob/master/A0.md)** — Voice messages
- **[`nipAA`](https://github.com/block/buzz/blob/main/docs/nips/NIP-AA.md)** — Agent Auth
- **[`nipAZ`](https://github.com/ohstr/zapf-nips/blob/main/NIP-AZ.md)** — AltZap: zaps for energy-backed coins
- **[`nipB0`](https://github.com/nostr-protocol/nips/blob/master/B0.md)** — Web bookmarks
- **[`nipB7`](https://github.com/nostr-protocol/nips/blob/master/B7.md)** — Blossom media
- **[`nipcash`](https://github.com/flokiorg/lokihub/blob/main/docs/nips/NIP-CASH.md)** — Cash Hub: ecash system
- **[`nipcw`](https://github.com/flokiorg/lokihub/blob/main/docs/nips/NIP-CW.md)** — Circle Wallet: shared self-service wallets
- **[`nipIC`](https://github.com/ohstr/zapf-nips/blob/main/NIP-IC.md)** — Identity Connection: binds Web Identity accounts to Nostr pubkeys
- **[`nipLS`](https://github.com/ohstr/zapf-nips/blob/main/NIP-LS.md)** — Local Signer: NIP-46 over a unix socket (`bunker+unix://`), client and policy-gated server
- **[`nipOA`](https://github.com/block/buzz/blob/main/docs/nips/NIP-OA.md)** — Owner Attestation

### Relay engine and infrastructure

- **`relay`** — Embeddable relay engine
- **`relay/client`** — Relay client (WebSocket, NWC)
- **`relay/migrations`** — Event store schema migrations
- **`search`** — Profile search indexing/ranking
- **`config`** — Embedded YAML config for search
- **`wire`** — Relay wire-protocol packet types
- **`huddle/wire`** — Huddle audio frame codec: per-frame header and relay routing prefix (binary, separate from the Nostr socket)
- **`huddle/room`** — Huddle audio room: peer registry, routing-identity allocation, and real-time frame fan-out over a transport-agnostic `Sink`
- **`huddle/wsaudio`** — Huddle audio WebSocket endpoint: NIP-42 handshake, room admission, frame relay, heartbeat
- **`utils`** — Shared event/key/logging helpers

NIP packages with relay-side concerns (NIP-22/34/47/48/57/65/88/90/B0/B7) stay
dependency-free on their own; blank-import their `relayreg` subpackage to
declare relay support, e.g. `import _ "github.com/ohstr/nmilat/nip57/relayreg"`.
See "Run a relay" below.

Runnable embedding patterns, at increasing levels of control, live in
[`examples/`](examples/) — not an importable package, just reference code to
copy from.

## Embedding nmilat

An embedder gets several independent `http.Handler`s and composes them
itself — nmilat ships no router or mux of its own:

- **`relay.Relay`** (or `relay.SessionHandler` directly) — the Nostr relay:
  NIP-11 info document and WebSocket upgrade on one path.
- **[`nip86.Handler`](nip86)** — the NIP-86 relay management API,
  NIP-98-authenticated, on whatever path the embedder mounts it.
- **`relay.NewQueryHandler`** — `POST /query`: a NIP-98-authenticated HTTP
  bridge, a one-shot alternative to a WebSocket REQ/EOSE round trip. The
  body is a JSON array of plain NIP-01 filters; the response is the
  matching stored events as a flat JSON array. This is the baseline case
  of buzz's own NIP-CW (not this module's unrelated `nipcw` package,
  which is NIP-CASH's Circle Wallet and merely shares the short name).
  NIP-98 binds identity/freshness, not authorization by itself, but this
  endpoint is not exempt from whatever access control an equivalent REQ
  would get: pass the relay's `*nip11.Limitation`, `*relay.MembershipService`
  and `*relay.GroupsService` (the same instances `SessionHandler.Membership()`
  and `SessionHandler.Groups()` return, not second ones) and a
  `MembershipRequired` relay refuses a non-member here exactly as it would
  refuse their REQ, and private NIP-29 groups stay hidden from non-members.
- **[`huddle/wsaudio`](huddle/wsaudio)**'s handler — Huddle audio, on its
  own WebSocket upgrader because a binary audio frame would be a parse
  error on the Nostr socket's JSON decoder.

They can share one `*relay.EventStore` (`EventStore.Db()` is deliberately
exposed for an embedder's own buckets on the same file) and are mounted
under whatever `http.ServeMux` the embedder already has — see
[`examples/relay-with-management-api`](examples/relay-with-management-api)
for the relay + management-API + query-bridge composition, which mirrors
what [`ncli`](https://github.com/ohstr/ncli) does internally. Optional
NIPs opt in by `relayreg` blank-import (above), not by the relay package
importing them.

**Performance characteristics an embedder can rely on:** every logger is
`zerolog.Nop()` unless passed in via `WithLogger`/`WithEventStoreLogger` —
nothing is written anywhere by default; there is no reflection-based
validation or schema check on the event ingest/delivery hot path; writes
are batched into single bbolt transactions (`EventStore`'s task queue); and
the REQ delivery loop carries each matched event's bytes from the scan
straight through to the wire reply, rather than re-reading the store per
event (see `docs/relay-scan-transaction-blocks-under-load.md` for the
before/after numbers).

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
	defer func() { _ = rl.Close() }()

	log.Fatal(http.ListenAndServe(":8080", rl))
}
```

(Runnable as [`examples/basic-relay`](examples/basic-relay).)

`relay.New` includes NIP-11 relay-info negotiation and starts profile
verification, with search disabled. For storage tuning, a search service, or
session options (CORS allowlist, NIP-26 delegation, ...), build the store
and handler directly with `relay.NewEventStore`/`relay.NewSessionHandler`
instead — see [`examples/full-relay`](examples/full-relay).

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

`ReadEventsFromRelayWithAuth` is the counterpart for a private/restricted
target: pass a `signingKeyHex` and it handles the NIP-42 handshake itself.
It also returns a `restricted bool` -- an empty `events` with `restricted
== true` means the relay refused the query, not that nothing matched.

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

### Create and manage a NIP-29 group

`nip29` covers the self-service group surface -- create/edit/delete,
membership and roles, invites, and pins. A group defaults to **private
and closed** on creation; see `ncli groups` for a CLI that also adds
NIP-29's recommended "previous" tag, which these constructors don't:

```go
package main

import (
	"context"
	"fmt"
	"net/url"

	"github.com/ohstr/nmilat/nip29"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

func main() {
	relayURL, _ := url.Parse("wss://relay.ohstr.com")
	conn, err := relayclient.Connect(context.Background(), relayURL)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	createEv := nip29.NewCreateGroup(ownerPubkeyHex, "standup")
	if err := createEv.Sign(ownerPrivateKeyHex); err != nil {
		panic(err)
	}
	if _, err := conn.Publish(context.Background(), createEv); err != nil {
		panic(err)
	}

	editEv := nip29.NewEditMetadata(ownerPubkeyHex, "standup", nip29.GroupMetadataParams{
		Name:    "Standup",
		About:   "Daily sync",
		Private: true, // omitting this would flip the group public
		Closed:  true,
	})
	if err := editEv.Sign(ownerPrivateKeyHex); err != nil {
		panic(err)
	}
	if _, err := conn.Publish(context.Background(), editEv); err != nil {
		panic(err)
	}

	addEv := nip29.NewPutUser(ownerPubkeyHex, "standup", memberPubkeyHex, "admin")
	if err := addEv.Sign(ownerPrivateKeyHex); err != nil {
		panic(err)
	}
	res, err := conn.Publish(context.Background(), addEv)
	if err != nil {
		panic(err)
	}
	fmt.Println("member added:", res.Accepted, res.Message)

	noteEv := nip29.NewCreateGroup(ownerPubkeyHex, "standup-notes")
	if err := noteEv.Sign(ownerPrivateKeyHex); err != nil {
		panic(err)
	}
	if _, err := conn.Publish(context.Background(), noteEv); err != nil {
		panic(err)
	}

	// NIP-29 "Subgroups": standup-notes hangs off standup. The submitter
	// must be an admin of both groups, and both must share the same
	// Private setting -- a signed kind:39000 can't be redacted per
	// viewer, so linking groups with different visibility would leak
	// one group's id through the other's public side.
	subEv := nip29.NewEditMetadata(ownerPubkeyHex, "standup-notes", nip29.GroupMetadataParams{
		Parent:  "standup",
		Private: true,
		Closed:  true,
	})
	if err := subEv.Sign(ownerPrivateKeyHex); err != nil {
		panic(err)
	}
	if _, err := conn.Publish(context.Background(), subEv); err != nil {
		panic(err)
	}
}
```

### Create a meeting space and send a live chat message (NIP-53)

`nip53` covers live streams, meeting spaces and their rooms, presence,
and live chat. A meeting space (kind:30312) needs a `d` tag, `room`,
`status`, `service`, and at least one `Host` provider:

```go
package main

import (
	"context"
	"fmt"
	"net/url"

	"github.com/ohstr/nmilat/nip53"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

func main() {
	spaceEv := nip53.NewMeetingSpace(nip53.MeetingSpaceParams{
		Pubkey:     hostPubkeyHex,
		Identifier: "standup-space",
		Room:       "standup-space",
		Status:     "live",
		Service:    "https://ohstr.com",
		Providers:  []nip53.Participant{{Pubkey: hostPubkeyHex, Role: nip53.RoleHost}},
	})
	if err := spaceEv.Sign(hostPrivateKeyHex); err != nil {
		panic(err)
	}

	spaceAddr, err := nip53.SpaceATag(hostPubkeyHex, "standup-space")
	if err != nil {
		panic(err)
	}

	chatEv := nip53.NewLiveChatMessage(nip53.LiveChatMessageParams{
		Pubkey:   senderPubkeyHex,
		Activity: spaceAddr,
		Content:  "on my way, 2 min",
	})
	if err := chatEv.Sign(senderPrivateKeyHex); err != nil {
		panic(err)
	}

	relayURL, _ := url.Parse("wss://relay.ohstr.com")
	conn, err := relayclient.Connect(context.Background(), relayURL)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	if _, err := conn.Publish(context.Background(), spaceEv); err != nil {
		panic(err)
	}
	res, err := conn.Publish(context.Background(), chatEv)
	if err != nil {
		panic(err)
	}
	fmt.Println("chat message accepted:", res.Accepted, res.Message)
}
```

### Enroll and remove a relay member (NIP-43)

`nip43` is relay-wide membership, independent of NIP-29 groups. A
relay's kind:8000/8001 events only *announce* an add or remove; publishing
one changes nothing. Membership changes come from a user's invite claim
(`NewJoinRequest`, `NewLeaveRequest`), or from the embedder through the
relay's `MembershipService`:

```go
package main

import (
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/relay"
)

func main() {
	meta := &nip11.Metadata{Self: relaySelfPubkeyHex}
	store, err := relay.NewEventStore("relay.db", &meta.Limitation)
	if err != nil {
		panic(err)
	}
	defer store.Close()
	// the self key signs the kind:13534 member list each change publishes
	sh := relay.NewSessionHandler(store, meta, nil, relay.WithSessionPrivKey(relaySelfPrivateKeyHex))

	if err := sh.Membership().Join(memberPubkeyHex, []string{"vip"}); err != nil {
		panic(err)
	}
	if err := sh.Membership().Leave(memberPubkeyHex); err != nil {
		panic(err)
	}
}
```

Each `Join`/`Leave` takes effect on the member's already-open connections
and republishes the relay-signed kind:13534 member list, with roles.

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

### Mint, verify, and secure a cash-mode slice (NIP-CASH)

A **cash-mode** slice (`nipcash.Anyone()` as the recipient) has no
Nostr identity attached — whoever holds its `cash_secret` can spend it.
`CheckClaim` confirms a received slice is real before trusting it;
`RekeyCashSlice` then re-keys it under a fresh secret only the new
holder knows, so the old one stops working:

```go
package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ohstr/nmilat/nipcash"
	cashclient "github.com/ohstr/nmilat/nipcash/client"
)

func main() {
	ctx := context.Background()

	hub, err := cashclient.Connect(ctx, cashHubPairingURI)
	if err != nil {
		panic(err)
	}
	defer hub.Close()

	minted, err := hub.MintCash(ctx, nipcash.MintCashParams{
		Recipients: []nipcash.Allocation{nipcash.Send(nipcash.Anyone(), 21_000_000)},
		Expiry:     24 * time.Hour,
	})
	if err != nil {
		panic(err)
	}

	// One string to hand over: the combined "<token>#<cash_secret>"
	// presentation.
	billString := minted.CashToken + "#" + minted.Recipients[0].CashSecret

	// Recipient's side: split it, then verify it's real.
	token, secret := nipcash.SplitCashSliceString(billString)
	tok, err := nipcash.Decode(token)
	if err != nil {
		panic(err)
	}

	recipient, err := cashclient.Connect(ctx, token)
	if err != nil {
		panic(err)
	}
	defer recipient.Close()

	check, err := recipient.CheckClaim(ctx, tok, nipcash.NoLocalIdentity)
	if errors.Is(err, nipcash.ErrClaimNotFound) {
		panic("dead, already-claimed, or never a real slice")
	} else if err != nil {
		panic(err)
	}
	fmt.Println("verified:", check.AmountMillis, "millis, cash:", check.IsCash)

	// Re-key it: secured.NewSecret is the only copy, persist it now.
	secured, err := recipient.RekeyCashSlice(ctx, cashclient.RekeyCashSliceParams{
		CashSlice: nipcash.Source{
			WalletPubkey: tok.WalletPubkey,
			Amount:       check.AmountMillis,
			Credential:   nipcash.BySecret(secret),
		},
	})
	if err != nil {
		panic(err)
	}
	fmt.Println("secured — new secret only this wallet knows:", secured.NewSecret)
}
```

To merge with another same-issuer slice you already hold, add
`ConsolidateWith`, `InterimIdentity`, and `InterimCredential` to the same
call. `nipcash/client.TransferFromSources` does the reverse: send a
specific amount, drawing from and auto-consolidating several sources.

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

### NIP-34: git collaboration over Nostr

`nip34` covers the whole spec -- repository announcements/state, patches,
pull requests, issues, threaded replies (via `nip22`), status, grasp
lists, and `nostr://` clone URLs. Every event type follows the same
`New*`/`Parse*`/`Validate*` shape; the examples below walk through each
one, in the order a repository's activity actually happens.

#### Announce a repository and publish its state

```go
package main

import (
	"fmt"

	"github.com/ohstr/nmilat/nip34"
	"github.com/ohstr/nmilat/utils"
)

func main() {
	announceEv, err := nip34.NewRepositoryAnnouncement(nip34.RepositoryAnnouncementParams{
		Pubkey:               ownerPubkeyHex,
		Identifier:           "ngit",
		Name:                 "ngit",
		Description:          "git over nostr",
		Web:                  []string{"https://gitworkshop.dev/ngit"},
		Clone:                []string{"https://github.com/example/ngit.git"},
		Relays:               []string{"wss://relay.ngit.dev"},
		EarliestUniqueCommit: rootCommitHex,
		Maintainers:          []string{maintainerPubkeyHex},
		Hashtags:             []string{"git", "nostr"},
	})
	if err != nil {
		panic(err)
	}
	if err := announceEv.Sign(ownerPrivateKeyHex); err != nil {
		panic(err)
	}

	stateEv, err := nip34.NewRepositoryState(nip34.RepositoryStateParams{
		Pubkey:     ownerPubkeyHex,
		Identifier: "ngit",
		Refs: []nip34.Ref{
			{Name: "refs/heads/master", CommitID: tipCommitHex},
			{Name: "refs/tags/v1.0.0", CommitID: tagCommitHex},
		},
		Head: "refs/heads/master",
	})
	if err != nil {
		panic(err)
	}
	if err := stateEv.Sign(ownerPrivateKeyHex); err != nil {
		panic(err)
	}

	// What a subscriber does on receipt: verify, then parse.
	if err := nip34.ValidateRepositoryAnnouncement(announceEv); err != nil {
		panic(err)
	}
	repo, err := nip34.ParseRepositoryAnnouncement(announceEv)
	if err != nil {
		panic(err)
	}
	fmt.Println(repo.Name, repo.Clone, repo.Maintainers)

	// The repo's "a" tag address, for filtering patches/issues/PRs sent to it.
	repoAddr, err := utils.FormatATag(nip34.KindRepositoryAnnouncement, ownerPubkeyHex, repo.Identifier)
	if err != nil {
		panic(err)
	}
	fmt.Println("repo address:", repoAddr)
}
```

`ValidateRepositoryState`/`ParseRepositoryState` are the state event's own
counterparts, shown together with `New` above.

#### Submit a patch series, a revision, and a pull request

```go
package main

import (
	"fmt"

	"github.com/ohstr/nmilat/nip34"
)

func main() {
	repoAddr := "30617:" + ownerPubkeyHex + ":ngit"

	// Root patch: first in the series.
	rootPatch, err := nip34.NewPatch(nip34.PatchParams{
		Pubkey:          contributorPubkeyHex,
		Content:         "diff --git a/main.go b/main.go\n...", // `git format-patch` output
		RepoAddress:     repoAddr,
		RepositoryOwner: ownerPubkeyHex,
		IsRoot:          true,
		Commit:          newCommitHex,
		ParentCommit:    parentCommitHex,
		Committer: &nip34.Committer{
			Name: "Ada Contributor", Email: "ada@example.com",
			Timestamp: 1_700_000_000, TZOffsetMinutes: -60,
		},
	})
	if err != nil {
		panic(err)
	}
	if err := rootPatch.Sign(contributorPrivateKeyHex); err != nil {
		panic(err)
	}

	// Second patch in the same series: replies to the root patch.
	secondPatch, err := nip34.NewPatch(nip34.PatchParams{
		Pubkey:          contributorPubkeyHex,
		Content:         "diff --git a/util.go b/util.go\n...",
		RepoAddress:     repoAddr,
		RepositoryOwner: ownerPubkeyHex,
		ReplyTo:         rootPatch.ID,
		Commit:          secondCommitHex,
		ParentCommit:    newCommitHex,
	})
	if err != nil {
		panic(err)
	}
	if err := secondPatch.Sign(contributorPrivateKeyHex); err != nil {
		panic(err)
	}

	// A revised series (e.g. after review feedback): its first patch is
	// tagged root-revision and replies to the original root patch.
	revisionPatch, err := nip34.NewPatch(nip34.PatchParams{
		Pubkey:          contributorPubkeyHex,
		Content:         "diff --git a/main.go b/main.go\n... (v2)",
		RepoAddress:     repoAddr,
		RepositoryOwner: ownerPubkeyHex,
		IsRootRevision:  true,
		ReplyTo:         rootPatch.ID,
	})
	if err != nil {
		panic(err)
	}
	if err := revisionPatch.Sign(contributorPrivateKeyHex); err != nil {
		panic(err)
	}

	// For a change too large for a patch (spec: SHOULD use a PR over 60kb),
	// a pull request points at a branch on a regular git host instead.
	prEv, err := nip34.NewPullRequest(nip34.PullRequestParams{
		Pubkey:          contributorPubkeyHex,
		Content:         "Adds the cool feature described in issue #12.",
		RepoAddress:     repoAddr,
		RepositoryOwner: ownerPubkeyHex,
		Subject:         "Add cool feature",
		Labels:          []string{"enhancement"},
		Commit:          tipCommitHex,
		CloneURLs:       []string{"https://github.com/contributor/ngit.git"},
		BranchName:      "cool-feature",
	})
	if err != nil {
		panic(err)
	}
	if err := prEv.Sign(contributorPrivateKeyHex); err != nil {
		panic(err)
	}

	// Pushed more commits to the same branch: update the PR's tip.
	prUpdateEv, err := nip34.NewPullRequestUpdate(nip34.PullRequestUpdateParams{
		Pubkey:             contributorPubkeyHex,
		RepoAddress:        repoAddr,
		PullRequestEventID: prEv.ID,
		PullRequestAuthor:  contributorPubkeyHex,
		Commit:             newerTipCommitHex,
		CloneURLs:          []string{"https://github.com/contributor/ngit.git"},
	})
	if err != nil {
		panic(err)
	}
	if err := prUpdateEv.Sign(contributorPrivateKeyHex); err != nil {
		panic(err)
	}

	// Parsing a patch back out, e.g. after fetching it from a relay.
	parsed, err := nip34.ParsePatch(rootPatch)
	if err != nil {
		panic(err)
	}
	fmt.Println(parsed.IsRoot, parsed.Commit, parsed.Committer.Name)
}
```

`ParsePullRequest`/`ValidatePullRequest` and
`ParsePullRequestUpdate`/`ValidatePullRequestUpdate` mirror `ParsePatch`
above for the PR events.

#### Open an issue and thread replies (NIP-22)

Replies to an issue, patch, or PR follow NIP-22's `kind:1111` comment
shape; `nip34.NewReply`/`nip34.ParseReply` are a thin convenience layer
over the `nip22` package that also checks the thread actually roots at a
NIP-34 item:

```go
package main

import (
	"fmt"

	"github.com/ohstr/nmilat/nip34"
)

func main() {
	repoAddr := "30617:" + ownerPubkeyHex + ":ngit"

	issueEv, err := nip34.NewIssue(nip34.IssueParams{
		Pubkey:          contributorPubkeyHex,
		Content:         "The build is broken on main.",
		RepoAddress:     repoAddr,
		RepositoryOwner: ownerPubkeyHex,
		Subject:         "Build broken",
		Labels:          []string{"bug"},
	})
	if err != nil {
		panic(err)
	}
	if err := issueEv.Sign(contributorPrivateKeyHex); err != nil {
		panic(err)
	}

	// Top-level reply: RootEvent and ParentEvent are the same (issue).
	maintainerReply, err := nip34.NewReply(nip34.ReplyParams{
		Pubkey:    ownerPubkeyHex,
		Content:   "thanks for reporting, looking into it",
		RootEvent: issueEv,
	})
	if err != nil {
		panic(err)
	}
	if err := maintainerReply.Sign(ownerPrivateKeyHex); err != nil {
		panic(err)
	}

	// Nested reply: RootEvent stays the issue, ParentEvent is the previous
	// reply -- this is how a threaded discussion is built up.
	followUp, err := nip34.NewReply(nip34.ReplyParams{
		Pubkey:      contributorPubkeyHex,
		Content:     "any update?",
		RootEvent:   issueEv,
		ParentEvent: maintainerReply,
	})
	if err != nil {
		panic(err)
	}
	if err := followUp.Sign(contributorPrivateKeyHex); err != nil {
		panic(err)
	}

	// Parsing a reply back out (e.g. after fetching from a relay):
	// nip34.ParseReply is nip22.ParseComment plus a check that the thread's
	// root is actually an issue/patch/PR.
	comment, err := nip34.ParseReply(followUp)
	if err != nil {
		panic(err)
	}
	fmt.Println("replying to root", comment.Root.Pointer.Value, "kind", comment.Root.Kind)
	fmt.Println("direct parent", comment.Parent.Pointer.Value)
}
```

#### Set and resolve status

```go
package main

import (
	"fmt"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip34"
)

func main() {
	// Open is the implicit default; an explicit Open event re-opens a
	// previously closed/applied thread.
	openEv, err := nip34.NewStatus(nip34.StatusParams{
		Pubkey:          contributorPubkeyHex,
		Kind:            nip34.KindStatusOpen,
		RootID:          patchEventID,
		RepositoryOwner: ownerPubkeyHex,
		RootAuthor:      contributorPubkeyHex,
	})
	if err != nil {
		panic(err)
	}
	if err := openEv.Sign(contributorPrivateKeyHex); err != nil {
		panic(err)
	}

	// Applied/Merged: a maintainer merges a patch revision, citing it and
	// the resulting merge commit.
	appliedEv, err := nip34.NewStatus(nip34.StatusParams{
		Pubkey:             ownerPubkeyHex,
		Kind:               nip34.KindStatusApplied,
		RootID:             patchEventID,
		AcceptedRevisionID: revisionEventID,
		RepositoryOwner:    ownerPubkeyHex,
		RootAuthor:         contributorPubkeyHex,
		RevisionAuthor:     contributorPubkeyHex,
		AppliedPatches:     []nip34.QuotedPatch{{EventID: revisionEventID, Pubkey: contributorPubkeyHex}},
		MergeCommit:        mergeCommitHex,
		Content:            "merged, thanks!",
	})
	if err != nil {
		panic(err)
	}
	if err := appliedEv.Sign(ownerPrivateKeyHex); err != nil {
		panic(err)
	}

	// Closed: rejected without merging.
	closedEv, err := nip34.NewStatus(nip34.StatusParams{
		Pubkey:          ownerPubkeyHex,
		Kind:            nip34.KindStatusClosed,
		RootID:          patchEventID,
		RepositoryOwner: ownerPubkeyHex,
		Content:         "superseded by a different approach",
	})
	if err != nil {
		panic(err)
	}
	if err := closedEv.Sign(ownerPrivateKeyHex); err != nil {
		panic(err)
	}

	// Draft: not ready for review yet (set by the author).
	draftEv, err := nip34.NewStatus(nip34.StatusParams{
		Pubkey: contributorPubkeyHex,
		Kind:   nip34.KindStatusDraft,
		RootID: patchEventID,
	})
	if err != nil {
		panic(err)
	}
	if err := draftEv.Sign(contributorPrivateKeyHex); err != nil {
		panic(err)
	}
	fmt.Println("closed kind:", closedEv.Kind, "draft kind:", draftEv.Kind)

	// Resolving which status actually counts: a client subscribes to every
	// 1630-1633 event for a thread (see "Subscribe to a repository's
	// activity" below), parses each, and picks the winner per the spec --
	// latest by created_at, from the root author or a recognized
	// maintainer. A status from anyone else is ignored even if it's newer:
	fetched := []*nip34.Status{
		{Event: &nip01.Event{PubKey: contributorPubkeyHex, CreatedAt: 1_700_000_000}, Kind: nip34.KindStatusOpen, RootID: patchEventID},
		{Event: &nip01.Event{PubKey: ownerPubkeyHex, CreatedAt: 1_700_000_500}, Kind: nip34.KindStatusApplied, RootID: patchEventID, AcceptedRevisionID: revisionEventID},
		{Event: &nip01.Event{PubKey: strangerPubkeyHex, CreatedAt: 1_700_001_000}, Kind: nip34.KindStatusClosed, RootID: patchEventID}, // newer, but not authorized -- ignored
	}

	resolved := nip34.ResolveStatus(fetched, contributorPubkeyHex, []string{maintainerPubkeyHex, ownerPubkeyHex})
	if resolved == nil {
		panic("no authorized status found")
	}
	fmt.Println("resolved status kind:", resolved.Kind) // KindStatusApplied

	// A patch revision inherits its root's resolved status, unless the
	// root was merged and this wasn't the accepted revision -- then it's
	// implicitly closed.
	effective := nip34.ResolveRevisionStatus(revisionEventID, resolved)
	fmt.Println("revision's effective status:", effective) // KindStatusApplied: it matches AcceptedRevisionID
}
```

#### Publish a grasp server list

The git-hosting analogue of a NIP-65 relay list or NIP-B7 Blossom server
list -- the [grasp servers](https://github.com/nostr-protocol/nips/blob/master/34.md#user-grasp-list)
a user prefers for NIP-34 activity, in order:

```go
package main

import (
	"fmt"

	"github.com/ohstr/nmilat/nip34"
)

func main() {
	ev := nip34.NewGraspServerList(pubkeyHex, []string{
		"wss://relay.ngit.dev",
		"wss://grasp.example",
	})
	if err := ev.Sign(privateKeyHex); err != nil {
		panic(err)
	}

	list, err := nip34.ParseGraspServerList(ev)
	if err != nil {
		panic(err)
	}
	fmt.Println("preferred grasp servers, in order:", list.Servers)
}
```

#### Build and parse `nostr://` clone URLs

```go
package main

import (
	"fmt"

	"github.com/ohstr/nmilat/nip19"
	"github.com/ohstr/nmilat/nip34"
)

func main() {
	// Form 1: "nostr://<naddr>" -- wraps the repository announcement's
	// naddr (see "Encode & decode entities" above).
	naddr, err := nip19.EncodeAddr(nip19.EntityPointer{
		Identifier: "ngit",
		PublicKey:  pubkeyHex,
		Kind:       nip34.KindRepositoryAnnouncement,
		Relays:     []string{"wss://relay.ngit.dev"},
	})
	if err != nil {
		panic(err)
	}
	naddrForm := nip34.BuildCloneURLFromAddr(naddr)
	fmt.Println(naddrForm) // nostr://naddr1...

	parsed, err := nip34.ParseCloneURL(naddrForm)
	if err != nil {
		panic(err)
	}
	pointer, err := parsed.ResolveAddr()
	if err != nil {
		panic(err)
	}
	fmt.Println(pointer.Identifier, pointer.PublicKey, pointer.Kind)

	// Form 2/3: "nostr://<npub|nip05>/[<relay-hint>/]<identifier>" -- more
	// readable, resolved by looking up the owner's relay list instead of
	// embedding one.
	npub, err := nip19.EncodePublicKey(pubkeyHex)
	if err != nil {
		panic(err)
	}
	readableForm := nip34.BuildCloneURL(npub, "relay.ngit.dev", "ngit")
	fmt.Println(readableForm) // nostr://npub1.../relay.ngit.dev/ngit

	parsed2, err := nip34.ParseCloneURL(readableForm)
	if err != nil {
		panic(err)
	}
	fmt.Println(parsed2.Owner, parsed2.RelayHint, parsed2.Identifier)

	// A NIP-05 identifier works as the owner too, and the relay hint is
	// optional:
	nip05Form := nip34.BuildCloneURL("dev@example.com", "", "ngit")
	fmt.Println(nip05Form) // nostr://dev@example.com/ngit
}
```

#### Subscribe to a repository's activity from a relay

The "server/client" side of NIP-34 is just `nip01`'s generic filter
builder plus `relay/client`, the same as any other NIP here -- there's no
`nip34/client` package, since NIP-34 has no second transport to dial:

```go
package main

import (
	"context"
	"fmt"
	"net/url"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip34"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

func main() {
	relayURL, _ := url.Parse("wss://relay.ngit.dev")

	// Every content kind a repository's activity can arrive as, filtered
	// by the repo's own "a" tag address (the same one NewPatch/NewIssue/
	// NewPullRequest/NewStatus were given as RepoAddress).
	filter := nip01.NewFilter().
		WithKinds(
			nip34.KindPatch,
			nip34.KindPullRequest,
			nip34.KindPullRequestUpdate,
			nip34.KindIssue,
			nip34.KindStatusOpen,
			nip34.KindStatusApplied,
			nip34.KindStatusClosed,
			nip34.KindStatusDraft,
		).
		WithTag("a", repoAddr)

	events, err := relayclient.ReadEventsFromRelay(context.Background(), relayURL, nip01.NewSubscriptionFilterGroup(filter))
	if err != nil {
		panic(err)
	}

	for _, ev := range events {
		if err := ev.Verify(); err != nil {
			continue // bad signature, bad ID, or malformed -- skip it
		}

		switch ev.Kind {
		case nip34.KindPatch:
			patch, err := nip34.ParsePatch(ev)
			if err == nil {
				fmt.Println("patch:", patch.Commit)
			}
		case nip34.KindPullRequest:
			pr, err := nip34.ParsePullRequest(ev)
			if err == nil {
				fmt.Println("PR:", pr.Subject)
			}
		case nip34.KindPullRequestUpdate:
			upd, err := nip34.ParsePullRequestUpdate(ev)
			if err == nil {
				fmt.Println("PR update:", upd.Commit)
			}
		case nip34.KindIssue:
			issue, err := nip34.ParseIssue(ev)
			if err == nil {
				fmt.Println("issue:", issue.Subject)
			}
		default:
			if nip34.IsStatusKind(ev.Kind) {
				status, err := nip34.ParseStatus(ev)
				if err == nil {
					fmt.Println("status for", status.RootID, "->", status.Kind)
				}
			}
		}
	}

	// Replies (kind:1111) aren't repo-scoped by an "a" tag -- they're
	// threaded off the issue/patch/PR event directly -- so subscribe to
	// them by root instead:
	replyFilter := nip01.NewFilter().WithKinds(1111).WithTag("E", issueEventID)
	replies, err := relayclient.ReadEventsFromRelay(context.Background(), relayURL, nip01.NewSubscriptionFilterGroup(replyFilter))
	if err != nil {
		panic(err)
	}
	for _, ev := range replies {
		if reply, err := nip34.ParseReply(ev); err == nil {
			fmt.Println("reply:", reply.Content)
		}
	}
}
```

## Development

Uses [`just`](https://github.com/casey/just) for build automation:

```sh
# compile-check (library, no binary)
just build
# go test ./...
just test
# go vet ./...
just vet
# go mod tidy
just tidy
# build + vet + test
just check
```

## License

[Unlicense](LICENSE) — public domain.
