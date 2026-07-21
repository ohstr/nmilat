# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.2.5]

### Added
- `nipB7` Blossom media support expanded from server-list discovery alone
  to the full protocol (BUD-01 through BUD-12): Authorization tokens with
  a server-side verification check, Blob Descriptor and list types, NIP-94
  metadata tags, blob reports, pre-flight/payment headers, and the
  `blossom:` URI scheme.
- `nipB7/client` — an HTTP client for talking to Blossom servers: upload,
  download (with multi-server fallback), mirror, list, delete, and report,
  all streaming and context-aware.

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
