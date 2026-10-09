# Changelog

## [0.5.0]

NIP-CASH's private transport, NIP-29 groups hosted by the relay, huddle audio,
NIP-86 relay management and HTTP bridges, and a long run of relay access,
privacy and performance fixes.

### Added

- Adds `WithEventStoreScanSlotWait` (default 10s): a REQ that can't get a scan
  slot is answered `CLOSED` `error: relay busy, try again later` instead of
  never. ([#81](https://github.com/ohstr/nmilat/pull/81))
- Adds `WithEventStoreMaxConcurrentScans` (default 2 × NumCPU), so read load
  can't starve writes of disk I/O. ([#78](https://github.com/ohstr/nmilat/pull/78))
- Adds `nipcash/transport`, NIP-CASH's private transport: many requests in one
  padded, encrypted envelope, with per-item proofs and a node-signed Hub
  announcement. ([#39](https://github.com/ohstr/nmilat/pull/39))
- Adds the batch API on `nipcash/client` (`RedeemMany`, `StatusMany`,
  `TransferMany`, `ConsolidateMany`), which acts on many bills in one relay
  event so their number and timing stay private. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Adds `nipcash/client.BatchSession`, which fetches, verifies and caches a
  Hub's announcement. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Adds `ItemOutcome` and `SafeToResend`, which tell a refused batch item from
  one the Hub said nothing about. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Accepts a Hub reply split across several events (`seq`, `total`). ([#43](https://github.com/ohstr/nmilat/pull/43))
- Adds `cash_status`'s `scope` (`all` or `mine`, defaulting to `mine` on the
  private transport) and an `AttestationEvent`, so a connection-key recipient
  can read their own row. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Adds `mint_cash`'s optional `idempotency_key`, so a retried mint doesn't fund
  a second wallet. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Adds `GetInfoResult.PrivateMethods`, naming the bill methods a Hub serves only
  over the private transport. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Adds `BillState`, `CashStatus` and `CashStatusResult`; the `list_recipients`
  names stay as deprecated aliases for one release. ([#39](https://github.com/ohstr/nmilat/pull/39))
- Exports `nip01.Event.Serialize`, so a remote signer can produce the exact
  signed preimage. ([#39](https://github.com/ohstr/nmilat/pull/39))
- Adds `nip29` for NIP-29 relay-based groups, with `ModerationPolicy` for a
  relay's role rules. ([#38](https://github.com/ohstr/nmilat/pull/38))
- Hosts NIP-29 groups on the relay: create and delete, members and roles, join
  and leave, metadata, invites, pins and moderator delete. New groups are
  private and closed. ([#56](https://github.com/ohstr/nmilat/pull/56))
- Adds NIP-29 subgroups: a group can name a parent, cycles and cross-group
  admin are checked, and deleting a parent makes its children roots. ([#70](https://github.com/ohstr/nmilat/pull/70))
- Warns at startup when NIP-29 groups are hosted without `nip11.url`, which
  makes private groups invisible even to their creator. ([#72](https://github.com/ohstr/nmilat/pull/72))
- Adds `nip53` for live streams, meeting spaces and rooms, presence and live
  chat. ([#38](https://github.com/ohstr/nmilat/pull/38))
- Adds `nipA0` for voice messages and `nip71` for video events. ([#38](https://github.com/ohstr/nmilat/pull/38))
- Adds the huddle audio transport (`huddle/wire`, `huddle/room`,
  `huddle/wsaudio`), which relays Opus between peers without decoding it.
  ([#38](https://github.com/ohstr/nmilat/pull/38))
- Adds `Room.EvictPubkey` and `Manager.EvictPubkey`, which remove a pubkey from
  a live call. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Adds `nip86`, the Relay Management API, with `nip86.NewHandler` and CORS for
  browsers. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Adds `relay.NewQueryHandler`, which serves `POST /query`: NIP-98-signed HTTP
  queries with REQ's access rules. ([#50](https://github.com/ohstr/nmilat/pull/50))
- Adds `relay.NewEventsHandler`, which serves `POST /events`: one signed event
  over HTTP. ([#51](https://github.com/ohstr/nmilat/pull/51))
- Adds `examples/` with runnable embedding patterns. ([#50](https://github.com/ohstr/nmilat/pull/50))
- Adds `nip98.Verify` options for an allowlist, body binding and a trailing
  slash, and `nip98.VerifyAnyPubkey`. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Adds `MethodSwitchRelays` and `MethodLogout` to `nip46`. ([#42](https://github.com/ohstr/nmilat/pull/42))
- Adds `ValidateZapRequestForRelay` and `ValidateZapReceiptForRelay`, and
  `ErrMissingDescriptionHash`. ([#35](https://github.com/ohstr/nmilat/pull/35))
- Answers NIP-42 AUTH from `relay/client.Connection` when given
  `ConnectionConfig.SigningKeyHex`. ([#59](https://github.com/ohstr/nmilat/pull/59))
- Adds `Connection.AuthState`, `AuthMessage` and `AuthSettled`, which report
  the NIP-42 outcome. ([#61](https://github.com/ohstr/nmilat/pull/61))
- Adds `ReadEventsFromRelayWithAuth`, which retries once after authenticating
  when the relay refuses the first read. ([#61](https://github.com/ohstr/nmilat/pull/61))

### Changed

- Requires Go 1.26.9, which fixes nine standard-library vulnerabilities.
  ([#89](https://github.com/ohstr/nmilat/pull/89))
- Sends the NIP-42 AUTH challenge on every connection, not only when
  `auth_required` is on. ([#65](https://github.com/ohstr/nmilat/pull/65))
- Returns whether the relay refused the read from
  `ReadEventsFromRelayWithAuth`. This changes its signature. ([#65](https://github.com/ohstr/nmilat/pull/65))
- Wakes live subscriptions when a write commits, instead of polling every
  50ms. ([#81](https://github.com/ohstr/nmilat/pull/81))
- Rebuilds the store's indexes on first open. This upgrade is one way, so copy
  the database first. ([#37](https://github.com/ohstr/nmilat/pull/37))
- Enforces NIP-70: an event tagged `["-"]` is accepted only from its
  authenticated author, so NIP-43 clients must AUTH first. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Serves bill methods only through the `Client` over the private transport.
  This breaks callers of the standard transport. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Requires mint provenance and removes `MintSignature` from the cash params.
  This breaks callers that set it. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Requires every credential to name a usable relay. Credentials without one
  no longer decode. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Renames the `circle_wallet` field `available_mloki` to `available_millis`.
  This breaks readers of the old name. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Changes `RekeyCashSlice` to take its new target from the caller, so the
  secret can be saved before the call. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Returns the conversation key from `transport.WrapRequest`. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Refuses an envelope that repeats an identical request, and caps an item id
  at 256 bytes. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Delivers REQ events from the bytes the scan already read, making delivery
  about a third faster. ([#50](https://github.com/ohstr/nmilat/pull/50))
- Normalizes `RegisterLetteredNIP`'s id and panics on one that can't name a
  NIP. ([#38](https://github.com/ohstr/nmilat/pull/38))
- Takes the `*GroupsService` in `NewQueryHandler`, so `POST /query` applies
  REQ's NIP-29 visibility. ([#74](https://github.com/ohstr/nmilat/pull/74))

### Fixed

- Fixes reads starving under many open subscriptions; live subscriptions now
  read only new events. ([#81](https://github.com/ohstr/nmilat/pull/81))
- Returns NIP-77 and NIP-05 fetch errors (NIP-05: 503) instead of answering
  from partial results. ([#81](https://github.com/ohstr/nmilat/pull/81))
- Answers every EVENT with exactly one OK, including `error: relay busy` after
  10s queued. ([#78](https://github.com/ohstr/nmilat/pull/78))
- Retries a failed store batch event by event, so only the failing event is
  rejected. ([#78](https://github.com/ohstr/nmilat/pull/78))
- Fixes a data race when connections opened at the same time. ([#75](https://github.com/ohstr/nmilat/pull/75))
- Fixes a filter's `limit` returning the oldest events instead of the newest.
  ([#37](https://github.com/ohstr/nmilat/pull/37))
- Fixes `#h=1` matching nothing once a longer value such as `h=10` exists.
  ([#37](https://github.com/ohstr/nmilat/pull/37))
- Fixes NIP-77 reconciliation of events that share a timestamp. ([#37](https://github.com/ohstr/nmilat/pull/37))
- Fixes deleting an ephemeral event leaving its expiration entry. ([#37](https://github.com/ohstr/nmilat/pull/37))
- Fixes the relay rejecting about 73% of real zap receipts; ingest enforces
  only NIP-57's MUST rules. ([#35](https://github.com/ohstr/nmilat/pull/35))
- Fixes the swapped `have=` and `want=` values in a description-hash mismatch.
  ([#35](https://github.com/ohstr/nmilat/pull/35))
- Checks the PoW floor before the signature, the cheaper check. ([#39](https://github.com/ohstr/nmilat/pull/39))
- Stops NIP-59 setting the seal's `PubKey` to the private key before signing,
  and randomizes `created_at` on seals and wraps. ([#39](https://github.com/ohstr/nmilat/pull/39))
- Fixes `nipcw` missing the join result's fields. ([#39](https://github.com/ohstr/nmilat/pull/39))
- Fixes a tagless event's id, which was wrong on every relay. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Fixes batch replies being lost at EOSE, cash-mode bills not batching, and a
  nil proof breaking every proofless item. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Fixes four ways a hostile Hub or relay could mislead a batching client, and
  surfaces an envelope-level refusal per item. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Bounds collecting a reply by the envelope's own deadline. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Tries every relay hint in `NewNWCClient`, not only the first. ([#43](https://github.com/ohstr/nmilat/pull/43))
- Fixes `ParseNostrconnect` rejecting spec-compliant URIs, using only the first
  relay, and dropping `perms`. ([#42](https://github.com/ohstr/nmilat/pull/42))
- Fixes NIP-98 treating an anti-replay `nonce` tag as proof-of-work. ([#51](https://github.com/ohstr/nmilat/pull/51))
- Fixes `POST /query` ignoring its `limit`, and paging past same-second events
  with `BeforeID`. ([#52](https://github.com/ohstr/nmilat/pull/52))
- Redials and re-authenticates once in `ReadEventsFromRelayWithAuth` if the
  relay drops the connection mid-wait. ([#63](https://github.com/ohstr/nmilat/pull/63))
- Fixes a redundant CLOSE ending the whole session. ([#65](https://github.com/ohstr/nmilat/pull/65))
- Fixes a query without a group tag returning private groups' metadata to
  anyone. ([#66](https://github.com/ohstr/nmilat/pull/66))
- Fixes an authenticated read losing the race with its own AUTH. ([#66](https://github.com/ohstr/nmilat/pull/66))
- Fixes `COUNT` revealing how many private groups exist, and an unknown group
  being distinguishable from a private one. ([#70](https://github.com/ohstr/nmilat/pull/70))
- Withholds private group content from non-members by any filter, live tails
  and `COUNT` included. ([#74](https://github.com/ohstr/nmilat/pull/74))
- Lets only members post into a private or closed group. ([#74](https://github.com/ohstr/nmilat/pull/74))
- Purges a deleted group's events and never serves a deleted group's mirrors.
  ([#74](https://github.com/ohstr/nmilat/pull/74))
- Applies NIP-43 joins and removals to members' open connections, and
  publishes the kind:13534 member list. ([#74](https://github.com/ohstr/nmilat/pull/74))
- Applies REQ's access checks to `COUNT`, and refuses unauthenticated clients
  with `auth-required:`. ([#74](https://github.com/ohstr/nmilat/pull/74))
- Fixes every `#d` lookup naming no group being refused. ([#74](https://github.com/ohstr/nmilat/pull/74))
- Rejects another key's create of an existing group id. ([#74](https://github.com/ohstr/nmilat/pull/74))
- Fixes NIP-26 signing the wrong delegation string; re-issue older tokens.
  ([#74](https://github.com/ohstr/nmilat/pull/74))
- Reports a refused anonymous read in `ReadEventsFromRelayWithAuth`, and
  retries a read answered before AUTH landed. ([#74](https://github.com/ohstr/nmilat/pull/74))
- Bounds `NewConnection`'s handshake by the caller's context. ([#74](https://github.com/ohstr/nmilat/pull/74))

## [0.4.0]

NIP-CASH's bearer mode becomes cash mode; this release needs lokihub
0.5.0-rc.6 or later.

### Breaking

- Renames NIP-CASH's bearer mode to cash mode on the wire (`identity_type:
  "cash"`, `cash_secret`). Existing tokens are unaffected. ([#32](https://github.com/ohstr/nmilat/pull/32))
- Renames the Go API to match (`CashTarget`, `CashSecret`, `IsCash`,
  `SplitCashSliceString`, `RekeyCashSlice`, …), with no deprecated aliases.
  ([#32](https://github.com/ohstr/nmilat/pull/32))

## [0.3.2]

A fix for a relay that could freeze.

### Fixed

- Fixes the relay freezing until restarted when a write had to grow the
  database while a REQ was sending. ([#29](https://github.com/ohstr/nmilat/pull/29))

### Changed

- Removes debug logging from busy relay paths. ([#29](https://github.com/ohstr/nmilat/pull/29))

## [0.3.1]

A zap invoice helper and a consolidate fix.

### Added

- Adds `nip57.RequestZapInvoice`, which resolves a LUD-16 address and fetches
  a zap invoice in one call. ([#28](https://github.com/ohstr/nmilat/pull/28))
- Exports `utils.ParsePayMetadataChains` and `utils.FetchLud16PayResponse`.
  ([#28](https://github.com/ohstr/nmilat/pull/28))

### Changed

- Adds an optional `Content` to `nip57.ZapRequestParams`. ([#28](https://github.com/ohstr/nmilat/pull/28))

### Fixed

- Fixes `CashConsolidateParams.ParseResult` failing after a successful merge
  when the new wallet's token arrives unencrypted. ([#28](https://github.com/ohstr/nmilat/pull/28))

## [0.3.0]

Git collaboration over Nostr, and cash-slice lifecycle helpers.

### Added

- Adds `nip34` for git collaboration (repositories, patches, pull requests,
  issues, statuses) and `nip22` for comments. ([#23](https://github.com/ohstr/nmilat/pull/23))
- Adds `utils.FormatATag`. ([#23](https://github.com/ohstr/nmilat/pull/23))
- Adds `ResolvedConnectionKey`, `SplitBearerSliceString`, `CheckClaim` and
  `IsPubkeyTarget` to `nipcash`. ([#22](https://github.com/ohstr/nmilat/pull/22))
- Adds `RekeyBearerSlice`, `TransferFromSources` and `PartialProgressError` to
  `nipcash/client`. ([#22](https://github.com/ohstr/nmilat/pull/22))
- Adds `GetInfoResult.CircleWallet` and `FeeSkimMloki`, which were dropped on
  unmarshal. ([#21](https://github.com/ohstr/nmilat/pull/21))

### Changed

- Accepts a bearer or connection-key target in `cash_consolidate`, and renames
  `ErrConsolidateTargetNotPubkey` to `ErrConsolidateTargetInvalid`. ([#22](https://github.com/ohstr/nmilat/pull/22))

### Fixed

- Fixes `TransferFromSources` reusing a stale client, which failed every
  multi-source transfer. ([#22](https://github.com/ohstr/nmilat/pull/22))

## [0.2.9]

Fixes for stalled delivery and corrupted events.

### Fixed

- Defaults `DataWriteTimeout` to 30s, so one slow reader can't stall every
  subscription on its connection, and logs slow writes. ([#19](https://github.com/ohstr/nmilat/pull/19))
- Fixes `FindEventBytes` serving corrupted event JSON under load. ([#19](https://github.com/ohstr/nmilat/pull/19))

## [0.2.8]

Hub connection strings and NWC fixes.

### Added

- Adds `cashhub1…` and `circlehub1…` encodings for a Hub's connection, with an
  optional label. ([#16](https://github.com/ohstr/nmilat/pull/16))
- Adds `nip47.ParseResponseEventWithFallback` and
  `relay/client.SubscriptionClosedError`. ([#14](https://github.com/ohstr/nmilat/pull/14))

### Fixed

- Fixes `NWCClient` misreading untagged NIP-44 responses as NIP-04. ([#14](https://github.com/ohstr/nmilat/pull/14))
- Fixes a burst on one kind starving the other kinds in a live subscription.
  ([#15](https://github.com/ohstr/nmilat/pull/15))

## [0.2.7]

Identity Connection, NIP-CASH and NIP-CW, and a Go 1.26.8 minimum.

### Changed

- Requires Go 1.26.8, which clears several standard-library CVEs. ([#7](https://github.com/ohstr/nmilat/pull/7))
- Changes `nipAZ` to take an `Identity` instead of raw strings, sign
  internally, and require the on-behalf sender. This breaks existing callers.
  ([#4](https://github.com/ohstr/nmilat/pull/4))

### Added

- Adds `nipIC` for NIP-IC: attestations, identity connections, the npv1
  challenge and `nconnection` encoding. ([#4](https://github.com/ohstr/nmilat/pull/4))
- Adds `nipcash` and `nipcash/client` for NIP-CASH cash tokens. ([#9](https://github.com/ohstr/nmilat/pull/9))
- Adds `nipcw` and `nipcw/client` for NIP-CW circle wallets. ([#9](https://github.com/ohstr/nmilat/pull/9))

### Fixed

- Stops `NewAltZapReceipt` re-deriving `p`/`P` tags from the embedded
  request. ([#4](https://github.com/ohstr/nmilat/pull/4))
- Sizes `nipIC.NewChallenge`'s entropy to 16 bytes. ([#4](https://github.com/ohstr/nmilat/pull/4))
- Returns an error when the delete path fails to update the expiration index.
  ([#7](https://github.com/ohstr/nmilat/pull/7))
- Accepts an event whose PoW tag overclaims its difficulty unless `StrictPow`
  is on. ([#10](https://github.com/ohstr/nmilat/pull/10))

## [0.2.6]

AltZap moves to its own package.

### Changed

- Moves AltZap from `nip57` to `nipAZ`. This breaks imports of
  `nip57.AltZap*`. ([#2](https://github.com/ohstr/nmilat/pull/2))

### Added

- Lets `AltZapReceiptParams` set the receipt's `r`/`R`/`a`/`e` tags directly.
  ([#2](https://github.com/ohstr/nmilat/pull/2))

## [0.2.5]

A goroutine leak fix.

### Fixed

- Fixes `relay/client.Connection` leaking a goroutine when nobody reads its
  errors. ([#1](https://github.com/ohstr/nmilat/pull/1))

## [0.2.4]

Full Blossom support.

### Added

- Expands `nipB7` to the full Blossom protocol (BUD-01 through BUD-12). ([b479e6d](https://github.com/ohstr/nmilat/commit/b479e6d))
- Adds `nipB7/client`, an HTTP client for Blossom servers. ([b479e6d](https://github.com/ohstr/nmilat/commit/b479e6d))

### Removed

- Removes the unused `nip11.DelegationConfig`. ([781d85b](https://github.com/ohstr/nmilat/commit/781d85b))

## [0.2.3]

NIP-43 membership, agent auth and owner attestation.

### Added

- Adds NIP-43 membership: join, leave and invites, and a
  `membership_required` gate. ([5d29cc2](https://github.com/ohstr/nmilat/commit/5d29cc2))
- Adds `nipOA` for NIP-OA owner attestations. ([d102626](https://github.com/ohstr/nmilat/commit/d102626))
- Adds `nipAA` for NIP-AA agent auth, with virtual membership for agent keys.
  ([f315db9](https://github.com/ohstr/nmilat/commit/f315db9))
- Lets one connection hold several authenticated pubkeys. ([c50bdae](https://github.com/ohstr/nmilat/commit/c50bdae))
- Adds `relay.RegisterLetteredNIP` for NIPs such as B0 and B7. ([154c1b2](https://github.com/ohstr/nmilat/commit/154c1b2))

### Fixed

- Advertises lettered NIPs as strings in NIP-11. ([154c1b2](https://github.com/ohstr/nmilat/commit/154c1b2))
- Fixes `EventStore.Close` racing in-flight tasks, NIP-42 checking the event's
  own relay tag, PoW thresholds, disabled search, and the reader ignoring
  cancellation. ([6d69bb2](https://github.com/ohstr/nmilat/commit/6d69bb2))

## [0.2.2]

The first public release.

### Added

- Adds `nip01` and 28 NIPs, an embeddable bbolt-backed relay engine, a relay
  client and profile search. ([14592fa](https://github.com/ohstr/nmilat/commit/14592fa))
