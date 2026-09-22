# Changelog

## [0.3.2]

### Fixed

- The relay could freeze until restarted. A `REQ` kept its database read
  open while sending events to the client, so when a write needed to grow
  the database file, every other `REQ` and `EVENT` on the relay hung —
  even with healthy clients, and while health checks stayed green. The
  relay now finishes each read before sending events. (#29)

### Changed

- Removed debug logging from busy relay paths, so each request does less
  work. Warnings and errors are unchanged. (#29)

## [0.3.1]

### Added

- `utils.ParsePayMetadataChains`/`utils.FetchLud16PayResponse`: parse a
  LUD-06 pay response and list the Lightning-routable chains it
  advertises. Previously only available privately inside the relay's
  own profile-verification worker.
- `nip57.RequestZapInvoice`: a high-level zap helper — resolves a
  recipient's LUD-16 address, builds and signs the zap request, and
  fetches an invoice back in one call.

### Changed

- `nip57.ZapRequestParams` gained a `Content` field, so a zap request
  can carry an optional public comment.

### Fixed

- `nipcash.CashConsolidateParams.ParseResult` always decrypted
  `new_wallet_token` and returned an error if that failed, even though
  the merge itself had already succeeded. A bearer/connection_key target
  has no real pubkey yet, so the Hub delivers the token in the clear and
  decryption always failed for it. `ParseResult` now passes that token
  through unchanged; for a pubkey target it still decrypts with the first
  source's credential, but a decryption failure now preserves the raw
  value instead of returning an error.

## [0.3.0]

### Added

- `nip34`: NIP-34 (git stuff) — repository announcements (`kind:30617`) and
  state (`kind:30618`), patches (`kind:1617`), pull requests (`kind:1618`)
  and PR updates (`kind:1619`), issues (`kind:1621`), replies (built on the
  new `nip22` package), status events (`kind:1630`-`1633`) with
  `ResolveStatus`/`ResolveRevisionStatus` helpers implementing the spec's
  status-resolution rules, user grasp lists (`kind:10317`), and `nostr://`
  clone URL parsing/building. `nip34/relayreg` declares relay-side support.
- `nip22`: NIP-22 (Comment) — the generic `kind:1111` threading note that
  NIP-34 replies build on, scoped to a root event, addressable event, or
  NIP-73 external identifier. `nip22/relayreg` declares relay-side support.
- `utils.FormatATag`: renders a `kind:pubkey:d-value` "a" tag string, the
  build-side counterpart to the existing `utils.ParseATag`.
- `nipcash.ResolvedConnectionKey`: builds a `connection_key`-mode Recipient/
  Target from a `nipIC.ConnectionKey` the caller already has (e.g. decoded
  from an `nconnection1...` string via `nipIC.DecodeNConnection`), without
  re-hashing it from a raw external ID the caller may not have on hand.
  `nipcash.ConnectionKey` still hashes `(platform, externalID)` internally
  for the common case; this is the counterpart for a caller starting from
  the key itself.
- `nipcash.SplitBearerSliceString`: splits a bearer slice's combined
  `"<token>#<bearer_secret>"` presentation into its two parts.
- `nipcash.CheckClaim` / `nipcash/client.CheckClaim`: one call to check
  whether a token has a real, unclaimed recipient (bearer or pubkey).
- `nipcash.IsPubkeyTarget`: reports whether a `Target` is pubkey-identified.
- `nipcash/client.RekeyBearerSlice`: re-keys a bearer slice under a fresh
  secret, optionally merging it with other same-issuer sources.
- `nipcash/client.TransferFromSources`: transfers an amount drawn from one
  or more sources, auto-consolidating first if none alone covers it.
- `nipcash/client.PartialProgressError`: reports partial progress when the
  first of two chained calls above lands but the second fails.

### Changed

- `cash_consolidate` now accepts a bearer or connection_key `To` target,
  not just pubkey. `ErrConsolidateTargetNotPubkey` renamed to
  `ErrConsolidateTargetInvalid`.

### Fixed

- `TransferFromSources` reused a stale, wallet-bound client for its
  second call, so every multi-source transfer failed with `NOT_FOUND`.
  Now reconnects to the new wallet first.
- `nip47.GetInfoResult`/`PayInvoiceResult`/`PayKeysendResult`/`Transaction`
  had no field for a circle_hub's own `get_info` terms block or a
  circle_wallet payment's forwarding-fee skim — `encoding/json` silently
  dropped both on unmarshal, so no caller could ever see them. Added
  `GetInfoResult.CircleWallet` (new `CircleWalletInfo` type: available
  balance, max expiry, fees_ppm, circle policy) and `FeeSkimMloki` on the
  three payment-result types.

## [0.2.9]

### Fixed

- `relay.SessionConfig.DataWriteTimeout` defaulted to `0` (no deadline) on
  a connection's single shared outgoing pipe — every subscription and
  control message on one connection funnels through one goroutine making
  one blocking `conn.WriteJSON` call at a time, so a slow or unresponsive
  reader could silently stall delivery to every subscription on that
  connection, indefinitely. Default is now 30s (overridable, including
  back to `0`, via the existing `WithSessionWriteTimeouts`). `sendPacket`
  also now logs a warning when a single write exceeds 250ms — previously
  there was no observable signal for this at all. See PR #19 for the full
  root-cause writeup and regression tests. (#19)
- `relay/store.EventStore.FindEventBytes` returned a bbolt-transaction-
  scoped byte slice after its own read transaction had already closed —
  invalid per bbolt's own contract, and reproducibly served corrupted
  (NUL-byte) event JSON to a client under a held-for-a-while delivery
  backlog. Fixed by copying the bytes inside the transaction closure.
  (#19)

## [0.2.8]

### Added

- `nipcash.EncodeCashHubConnection`/`DecodeCashHubConnection` and
  `nipcw.EncodeCircleHubConnection`/`DecodeCircleHubConnection`: a
  `cashhub1...`/`circlehub1...` bech32 encoding of a Hub's own pairing data
  (wallet pubkey, relay(s), secret, optional human-readable label), for a
  single copy-paste-safe connection string instead of a raw
  `nostr+walletconnect://` URI. Each format's HRP is fixed internally, so a
  Cash Hub connection can't be mistaken for a Circle Wallet Hub one or vice
  versa. (#16)
- `nip47.ParseResponseEventWithFallback`: like `ParseResponseEvent`, but
  falls back to a caller-supplied encryption scheme instead of assuming
  NIP-04 when a response event carries no `encryption` tag of its own.
  (#14)
- `relay/client.SubscriptionClosedError`, returned by `NWCClient` calls when
  the relay sends a `CLOSED` message for the underlying subscription (e.g.
  after a "too many concurrent subscriptions" NOTICE), instead of the call
  hanging silently until `ctx`'s full timeout. (#14)

### Fixed

- `relay/client.NWCClient` misparsed untagged NIP-44 v2 responses as legacy
  NIP-04, defaulting to NIP-04 whenever a response didn't redeclare its own
  `encryption` tag instead of falling back to the scheme the client used
  for the original request — silently breaking decryption for wallets that
  reply in NIP-44 without redeclaring it. Fixed via
  `ParseResponseEventWithFallback`; `NWCClient` now passes its own known
  encryption as the fallback. (#14)
- `relay`'s combined-kind live-scan path (`SubscriptionFilter.Kinds` with
  more than one kind) drained one cursor's whole collected batch through
  the subscription's buffered outgoing channel before the next cursor even
  ran its own collect — a sustained burst on one kind could starve every
  other kind sharing that filter for as long as a slow consumer took to
  drain the busy kind's backlog. Cursors sharing a combined-kind filter now
  collect into one recency-ordered queue before a single end-of-pass
  flush, so events from different kinds interleave by recency instead of
  by cursor position. The bounded (non-live) query path and its `Limit`
  semantics are unaffected. (#15)

## [0.2.7]

### Changed

- Minimum Go version raised from 1.25.5 to 1.26.8, to pick up upstream fixes
  for several stdlib CVEs (`crypto/tls`, `crypto/x509`, `net/http`) that
  `govulncheck` flags against older patch versions — not nmilat code bugs,
  but real reachable vulnerabilities in code this module's `relay/client`
  and `nipB7/client` call into. (#7)
- **Breaking:** `AltZapRequestParams`/`AltZapReceiptParams` no longer take
  raw `Recipient`/`Sender`/`*Provider` strings — both are now `Identity`,
  built via `nipAZ.Pubkey(hex)`, `nipAZ.Connection(platform, externalID)`,
  or `nipAZ.ResolvedConnection(key, platform)`. `WebIdentity` and
  `ConnectionKey` are re-exported from the new `nipIC` package under
  `nipAZ`'s own names. (#4)
- **Breaking:** `NewAltZapRequest`, `NewAltZapOnBehalfRequest`, and
  `NewAltZapReceipt` now sign internally via a required `PrivateKey` param
  and return `(*nip01.Event, error)` — callers no longer call `.Sign()`
  themselves. (#4)
- **Breaking:** `NewAltZapOnBehalfRequest` now takes `sender` as a required
  positional `Identity` argument instead of an optional params field, so an
  invalid kind 5523 (missing `P` tag) can't be constructed. (#4)

### Added

- New `nipIC` package (NIP-IC, Identity Connection): binds Web Identity
  accounts (Discord, Telegram, ...) to Nostr pubkeys via a signed IA
  attestation. `NewAttestation`/`ParseAttestation`/`ValidateAttestation` for
  Kind 35522, `ParseIdentityConnection`/`ValidateIdentityConnection` for Kind
  35521, `NewChallenge`/`ChallengeToken.Verify` for the npv1 cross-IA
  challenge binding, and `EncodeNConnection`/`DecodeNConnection` for the
  `nconnection` bech32 profile-link format. (#4)
- New `nipcash` package (NIP-CASH, Cash Hub): mint, hold, redeem, transfer,
  split, and consolidate cash tokens (`lokicash1...`/`satscash1...`) — a
  Chaumian ecash system built directly on NIP-47. `MintCash`/`CashRedeem`/
  `CashTransfer`/`CashConsolidate`/`ListRecipients` request/response shapes;
  `Recipient`/`Credential`/`BearerTarget`/`Source` abstractions (the
  `pubkey`/`connection_key` cases build on `nipAZ.Identity`/`nipIC`, so no
  caller ever hand-rolls a `connection_key` hash or an IA-attestation
  reference); the cash-token TLV codec (`Decode`/`Encode`); mint-provenance
  verification (`VerifyProvenance`, recoverable ECDSA). Defines kind 23198
  (its own per-call claim proof — deliberately not NIP-IC's kind 35521,
  which is long-lived/reusable by design and would reopen the replay
  surface this proof exists to close on a shared connection). `nipcash/client`
  is the NWC transport built on top, mirroring `nipB7`/`nipB7/client`'s
  protocol/dial-out split. (#9)
- New `nipcw` package (NIP-CW, Circle Wallet): self-service
  `create_circle_wallet` for a host's own node, extended to a group who
  don't run one themselves. Defines kind 23199 (its own per-call identity
  proof, same reasoning as `nipcash.KindClaimProof`). `nipcw/client` is the
  NWC transport built on top. (#9)

### Fixed

- **Security:** `nipAZ.NewAltZapReceipt` no longer silently re-derives its
  `p`/`P` tags by parsing the embedded request's `description` JSON — it now
  only ever uses `Identity` values the caller explicitly passed, closing a
  gap where a tampered embedded request could redirect a receipt's
  attribution. (#4)
- `nipIC.NewChallenge`'s session entropy is now 16 bytes (32 hex chars),
  matching its real caller (a token posted publicly); it was previously 12
  hex chars, sized for a short human-typeable pre-auth code that belongs to
  a different caller entirely. (#4)
- `relay`'s event-delete path (used by NIP-09 deletion and replaceable-event
  supersession) now returns an error if writing to the expiration index
  fails, instead of silently swallowing it and leaving the index only
  partially updated. (#7)
- `relay` no longer rejects an event whose `nonce` tag overclaims its NIP-13
  difficulty regardless of config — that check now honors
  `Limitation.StrictPow`, same as the existing `MinPowDifficulty` floor. (#10)

## [0.2.6]

### Changed

- **Breaking:** AltZap is now its own package, `nipAZ` (NIP-AZ), instead of
  living inside `nip57`. Update the import to `github.com/ohstr/nmilat/nipAZ`
  and the qualifier from `nip57.` to `nipAZ.` — names are unchanged
  (`AltZapRequest`, `NewAltZapReceipt`, etc.). Blank-import `nipAZ/relayreg`
  instead of relying on `nip57/relayreg` to declare it. (#2)

### Added

- `AltZapReceiptParams` can now set the receipt's `r`/`R`/`a`/`e` tags
  directly (`ResolvedRecipientPubkey`, `ResolvedSenderPubkey`, `Coordinate`,
  `EventID`), for callers whose `p`/`P` identity isn't a raw pubkey. (#2)

## [0.2.5]

### Fixed

- `relay/client.Connection`'s read/write/ping loops could leak a goroutine
  forever, blocked sending on `Connection.errors`, if nobody was actively
  reading `Errors()` at the exact moment a read/write error arrived --
  exactly what tends to happen during ordinary shutdown, when a caller
  cancels its context and stops its own error-consuming loop just before
  the connection notices the now-dead socket. Every other channel
  operation in `connection.go` already escaped via `closeCh`/`ctx.Done()`
  when nobody was listening; the `errors <-` sends now do too.

## [0.2.4]

### Added
- `nipB7` Blossom media support expanded from server-list discovery alone
  to the full protocol (BUD-01 through BUD-12): Authorization tokens with
  a server-side verification check, Blob Descriptor and list types, NIP-94
  metadata tags, blob reports, pre-flight/payment headers, and the
  `blossom:` URI scheme.
- `nipB7/client` — an HTTP client for talking to Blossom servers: upload,
  download (with multi-server fallback), mirror, list, delete, and report,
  all streaming and context-aware.

### Removed
- `nip11.DelegationConfig` — a dead, unused duplicate of `relay.DelegationConfig`
  (the type actually wired up for NIP-26 delegation) that never had any
  callers.

## [0.2.3]

### Added
- NIP-43 relay group membership: join/leave/invite request handling,
  role-gated admin plumbing (member listing, invite issuance/deletion),
  and a `membership_required` access gate enforced per-signer on
  REQ/EVENT/COUNT.
- `nipOA` — NIP-OA Owner Attestation: parsing and BIP-340 signature
  verification of the "auth" tag's owner/conditions/sig format, tested
  against the spec's official vectors.
- `nipAA` — NIP-AA Agent Auth: virtual membership for agent keys,
  granted at AUTH time via the spec's 6-step verification (freshness
  window, credential evaluation, owner-membership check), plus
  optional per-event `kind=` enforcement.
- Multi-identity `Session` model: a connection can hold more than one
  independently-authenticated pubkey (e.g. a human key plus one or
  more agent keys), each with its own resolved membership status.
- `relay.RegisterLetteredNIP` and `nip11.NIPID`/`NIP()`/`NIPLetter()`
  for declaring letter-suffixed NIPs (NIP-B0, NIP-B7) alongside
  numbered ones.

### Fixed
- `supported_nips` in the NIP-11 document no longer hex-coerces
  lettered NIPs (NIP-B0, NIP-B7) into meaningless integers — they now
  serialize as their literal string ID.
- `EventStore.Close` waits out in-flight tasks instead of racing
  `db.Close` against them.
- NIP-42 AUTH's `relay` tag is checked against the configured relay
  URL instead of the event's own tag.
- NIP-13 PoW min/strict thresholds are read from `nip11.Limitation` as
  the single source of truth.
- NIP-50 search handler replies cleanly when search is disabled
  instead of silently returning empty results.
- Relay client reader honors context cancellation instead of hanging
  until the socket is force-closed.

## [0.2.2]

Initial public release.

### Added
- Core Nostr event/filter/subscription primitives (`nip01`).
- 28 implemented NIPs: encryption (`nip04`, `nip44`, `nip49`), identity
  (`nip05`, `nip19`), deletion (`nip09`), relay info (`nip11`), proof of
  work (`nip13`), event treatment (`nip16`), private DMs and gift wraps
  (`nip17`, `nip59`), long-form content (`nip23`), delegation (`nip26`),
  parameterized replaceable events (`nip33`), expiration (`nip40`),
  auth (`nip42`, `nip98`), remote signing (`nip46`), wallet connect
  (`nip47`), proxy tags (`nip48`), zaps (`nip57`), relay list metadata
  (`nip65`), negentropy sync (`nip77`), polls (`nip88`), data vending
  machines (`nip90`), web bookmarks (`nipB0`), and Blossom media server
  lists (`nipB7`).
- Embeddable relay engine (`relay`): bbolt-backed event store, sessions,
  wire handlers, signature verification.
- Relay client (`relay/client`) for connecting to remote relays over
  WebSocket.
- Profile search indexing/ranking (`search`).
