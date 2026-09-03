# Changelog

## [0.2.7]

### Changed

- Minimum Go version raised from 1.25.5 to 1.26.8, to pick up upstream fixes
  for several stdlib CVEs (`crypto/tls`, `crypto/x509`, `net/http`) that
  `govulncheck` flags against older patch versions — not nmilat code bugs,
  but real reachable vulnerabilities in code this module's `relay/client`
  and `nipB7/client` call into.

### Added

- New `nipIC` package (NIP-IC, Identity Connection): binds Web Identity
  accounts (Discord, Telegram, ...) to Nostr pubkeys via a signed IA
  attestation. `NewAttestation`/`ParseAttestation`/`ValidateAttestation` for
  Kind 35522, `ParseIdentityConnection`/`ValidateIdentityConnection` for Kind
  35521, `NewChallenge`/`ChallengeToken.Verify` for the npv1 cross-IA
  challenge binding, and `EncodeNConnection`/`DecodeNConnection` for the
  `nconnection` bech32 profile-link format.

### Fixed

- **Security:** `nipAZ.NewAltZapReceipt` no longer silently re-derives its
  `p`/`P` tags by parsing the embedded request's `description` JSON — it now
  only ever uses `Identity` values the caller explicitly passed, closing a
  gap where a tampered embedded request could redirect a receipt's
  attribution.
- `nipIC.NewChallenge`'s session entropy is now 16 bytes (32 hex chars),
  matching its real caller (a token posted publicly); it was previously 12
  hex chars, sized for a short human-typeable pre-auth code that belongs to
  a different caller entirely.
- `relay`'s event-delete path (used by NIP-09 deletion and replaceable-event
  supersession) now returns an error if writing to the expiration index
  fails, instead of silently swallowing it and leaving the index only
  partially updated.

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
