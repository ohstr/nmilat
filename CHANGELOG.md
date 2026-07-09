# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
