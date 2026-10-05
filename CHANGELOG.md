# Changelog

## [0.5.0]

_Cut as `v0.5.0-rc.3` on 2026-10-04._ This section stays open: 0.5.0 itself has
not been released, so everything under it is still pre-release and accumulating.
rc.2 is where the NIP-CASH private transport became usable from a client: the
batch API that spends many bills in one relay event, the breaking changes three
rounds of audit forced on the transport's own shapes, and the NIP-01
serialization fix that had made every tagless event's id wrong. rc.3 formalizes
the embeddable relay SDK -- `examples/`, a README "Embedding nmilat" section --
alongside the `PotentialEvent.Bytes` hot-path fix that removes a second
read transaction from REQ delivery, and adds the NIP-98-authenticated
`POST /query` HTTP bridge for buzz-relay compatibility (access-scoped by
NIP-43 membership exactly as REQ is).

### Added

- `relay.NewQueryHandler` serves `POST /query`: a NIP-98-authenticated HTTP
  bridge that takes a JSON array of plain NIP-01 filters and returns the
  matching stored events as a flat JSON array, a one-shot alternative to a
  WebSocket REQ/EOSE round trip for buzz-relay-compatible clients. It
  reuses the bytes `collectBatch` already captured at scan time
  (`PotentialEvent.Bytes`), so it pays no extra store read beyond the
  scan itself. `nip98.VerifyAnyPubkey` is the new primitive underneath:
  same checks as `Verify`, but for an endpoint where NIP-98 binds identity
  and freshness rather than gating on an allowlist. Per NIP-CW's own
  Access Scoping section, this is not exempt from whatever access control
  an equivalent REQ gets: given the relay's `*nip11.Limitation` and its
  `*MembershipService`, a `MembershipRequired` relay refuses a non-member
  caller here exactly as it would refuse their REQ, rather than serving
  everyone who can produce a valid signature; no membership service given
  fails closed rather than open. (#50)
- `relay/groups.go` hosts real NIP-29 group state for `kind:9007`
  create / `kind:9008` delete -- `nip29/` was structural validation only
  before this, with no record of which groups exist. Creation needs no
  prior NIP-43 relay membership, the creator becomes sole admin, and the
  group defaults to private+closed, mirrored into self-signed
  `kind:39000`/`39001`/`39002` the same way `relay/membership.go` mirrors
  NIP-43 membership. A REQ/COUNT naming a private group's id now requires
  an authenticated member of that group, or the private default wouldn't
  mean anything.
- `huddle/room.Sink` is the seam that makes a room transport-agnostic: a
  peer is admitted with a sink, and a WebSocket peer differs from one
  bridged onto another transport only in which sink it has. `ChannelSink` is
  the default -- bounded queues a writer goroutine drains -- and
  `Room.AddPeer` / `Manager.Join` take the sink to deliver to. (#38)
- `huddle/room.Frame` carries both shapes a sink might want: `Relayed`, the
  wire-ready bytes a WebSocket peer writes straight out, and `Author` plus
  `Client` for a sink that repacketizes, with `Frame.Payload` recovering the
  sender's header and the opaque Opus. The room builds `Relayed` once per
  broadcast and shares it, so adding the seam costs no extra allocation, and
  it never parses a frame on the broadcast path. (#38)
- `huddle/wsaudio` serves huddle audio over its own WebSocket: a NIP-42
  challenge/auth handshake, room admission, the binary frame relay, and a
  heartbeat that drops a peer which stops answering. It is a separate route
  with its own upgrader because the Nostr socket decodes every frame as JSON
  and a binary audio frame there is a parse error that tears the session
  down. (#38)
- Refusals carry a code a client can branch on -- `auth_failed`,
  `join_rejected`, `room_full`, `room_ended`, `upgrade_required` (with the
  room's actual version so a client can retry), `room_unavailable` and
  `huddle_audio_unavailable`. A disabled deployment answers with the last of
  those rather than an HTTP error that looks like a missing route. (#38)
- Membership policy is a hook, not built in: `Config.Authorize` is where a
  relay consults NIP-29 group state or NIP-43 relay access, so this package
  holds no policy of its own. (#38)
- The Origin header is not this endpoint's security boundary -- admission is
  gated by a signed challenge -- so an unset `AllowedOrigins` allows any
  origin. Defaulting the other way is what silently locks browsers out while
  every CLI client keeps working. (#38)
- `huddle/room.Manager` holds the live rooms by id, creating one on the
  first join and dropping it once the last peer leaves, so an idle process
  holds none. A join that fails against a room it had to create removes
  that room again -- otherwise a client failing admission repeatedly would
  leave an empty room per attempt until the cap was reached. (#38)
- `huddle/room` implements a huddle audio room: the peer registry, the
  routing identities it allocates, and the fan-out carrying one peer's
  frames to everyone else. A sender never receives its own frame, and the
  author's bytes are forwarded verbatim behind the routing prefix. (#38)
- A peer's audio queue holds 160 ms and **drops when full rather than
  blocking**, so one listener that stops draining cannot stall the peer who
  is talking. Control messages get their own larger queue and a full one is
  reported instead of swallowed: they carry the index-to-pubkey mapping a
  client needs, so losing one misattributes every later frame. (#38)
- Routing indices sweep forward through the whole 0..254 space instead of
  recycling the lowest free one, and each index carries an epoch that
  increments on reuse -- without it, a late frame from a departed peer is
  indistinguishable from one sent by whoever took its index. (#38)
- `huddle/wire` implements the huddle audio frame protocol: the 8-byte
  per-frame header clients author (sequence, 48 kHz timestamp, dBov level,
  DTX flag) and the routing prefix a relay prepends when fanning a frame
  out -- one peer index, plus a per-index epoch from protocol v3 so a frame
  from a departed peer cannot be mistaken for one from whoever reused its
  index. The Opus payload stays opaque throughout, which is what lets a
  relay carry audio without linking a codec. (#38)
- `huddle/wire.ClampLevel` keeps the client-authored level in its canonical
  -127..0 range without ever dropping the frame it came on. The level is
  untrusted telemetry, and bad telemetry must not become audible loss. (#38)
- `nip71` implements NIP-71 (Video Events): normal (kind 21) and short (22)
  videos plus their addressable counterparts (34235/34236), with the NIP-92
  `imeta` variants that carry each rendition and audio track. A variant
  keeps unmodelled imeta properties in `Extra`, so round-tripping an event
  never silently drops information NIP-92 or NIP-94 defines. (#38)
- `nip71.Video.HasPlayableVariant` answers whether any variant has a url a
  client could play. Parsing does not require one: the spec calls imeta the
  primary source of video information but never states it as a MUST. (#38)
- `nip71/relayreg` declares NIP-71 in a relay's NIP-11 document and
  validates video events on ingest. (#38)
- `nipA0` implements NIP-A0 (Voice Messages): root voice notes (kind 1222)
  and replies (1244), plus the optional NIP-92 `imeta` preview carrying a
  waveform and duration so a client can draw one without downloading the
  audio. `DurationSet` separates an absent duration from a zero-second
  one, and the spec's 60-second guidance is reported by
  `ExceedsRecommendedDuration` rather than enforced, since it is a SHOULD
  for publishers and not grounds for a relay to reject anything. (#38)
- `nipA0.ReplyScopes` returns a 1244 reply's NIP-22 root and parent by
  delegating to `nip22`, so the pointer-tag rules are not duplicated. (#38)
- `nipA0/relayreg` declares NIP-A0 in a relay's NIP-11 document and
  validates voice messages on ingest. (#38)
- `nip29` implements NIP-29 (Relay-based Groups): the moderation events
  that change group state (kinds 9000-9020), the join and leave requests
  users send (9021/9022), and the relay-authored events that mirror the
  result -- metadata, admins, members, roles, live AV participants and
  pinned events (39000-39005). NIP-28 is unrecommended upstream in favour
  of this, so there is no nip28. (#38)
- `nip29.ModerationPolicy` lets a relay declare which roles may perform
  which moderation kinds. The spec states the mapping is relay-specific
  and that relays MUST check it, so this is a type to fill in rather than
  a built-in guess at what "admin" means. (#38)
- `nip29.GroupMetadata.SupportsKind` honours the absent-vs-empty
  distinction on `supported_kinds`, which the spec gives opposite
  meanings: no tag means every kind is supported, an empty tag means none
  are -- the AV-only group case. (#38)
- `nip29.TimelineReferences` parses the `previous` tag's 8-character event
  prefixes, the hack that stops a group message being replayed into a fork
  of that group out of context. (#38)
- `nip29/relayreg` declares NIP-29 in a relay's NIP-11 document and
  structurally validates group events on ingest. Role authorization and
  the relay-`self` signer check stay in the relay, which has the state to
  decide them. (#38)
- `nip53` implements NIP-53 (Live Streaming and Spaces): the live
  streaming event (kind 30311), the meeting space that hosts audio/video
  rooms (30312) and the meetings held in one (30313), listener presence
  (10312) and live chat (1311), with parse/validate/construct for each.
  A space's `service` tag is transport-neutral, so a room can be reached
  over any media transport rather than a single vendor's. (#38)
- `nip53.IsStale` and `nip53.IsPresenceFresh` implement the spec's two
  liveness heuristics -- a `live` activity with no update for an hour may
  be treated as ended, and presence older than a window should be
  filtered -- so callers stop reinventing them inconsistently. (#38)
- `nip53.SignParticipationProof` and `nip53.VerifyParticipationProof`
  implement proof of agreement to participate, the signature over an
  activity's `a` tag that stops an event owner listing accounts who never
  agreed to join. (#38)
- `nip53/relayreg` declares NIP-53 in a relay's NIP-11 document and
  auto-validates all five kinds on ingest, so a relay hosting rooms
  rejects structurally broken ones instead of storing them. (#38)
- `nip57.ValidateZapRequestForRelay` and `nip57.ValidateZapReceiptForRelay`
  validate zap events the way a relay ingesting someone else's traffic
  should: every MUST-level rule in NIP-57 is enforced, while the rules the
  spec states as SHOULD or optional are tolerated. `ValidateZapRequest` and
  `ValidateZapReceipt` are unchanged and remain the right choice when
  settling or accounting for your own zaps. (#35)
- `nip57.ErrMissingDescriptionHash`, returned when a receipt's invoice
  carries no description hash at all. That case previously surfaced as
  `ErrDescriptionHashMismatch` with an empty `want=`, which reads as
  evidence the receipt belongs to a different zap when it is nothing of the
  sort. (#35)
- `nipcash/transport` implements NIP-CASH's private transport: a batch
  envelope that carries several requests under one encryption, per-item
  proofs, a response envelope with its own reply-key derivation, and a
  node-signed hub announcement so a client can find and authenticate a Hub's
  inbox. Envelope size limits are configurable, and the consolidate source
  cap is derived from them rather than fixed, so it cannot be set above what
  an envelope can actually carry. (#39)
- Padding hides how many items an envelope holds: a one-item request and a
  six-item one are the same size on the wire, and an unserved item is
  omitted from the response rather than answered with an error — an error
  would confirm the existence of a wallet the caller could not prove it
  holds. (#39)
- `nipcash.BillState` gives the three-outcome bill read (live, spent,
  indeterminate) one reusable representation, and `CashStatus`/
  `CashStatusResult` replace the `list_recipients` naming throughout. The
  old names remain as deprecated aliases for one release, and
  `Client.ListRecipients` deliberately still sends the old wire method so
  the client and the Hub can migrate independently. (#39)
- `nip01.Event.Serialize` is exported, so a remote signer can produce the
  exact preimage the signature covers. (#39)
- `nip46.MethodSwitchRelays` and `nip46.MethodLogout` name the two standard
  methods the package was missing, so a signer can answer them instead of
  reporting them unsupported. (#42)
- `nip98.Verify` takes an `Options` and returns the pubkey that
  authenticated, so a caller can scope what the request may do. It adds the
  three things `VerifyAuthHeader` could not express: a set of allowed
  pubkeys rather than one, `payload`-tag verification binding the body to
  the signature, and an opt-in trailing-slash relaxation of the `u` tag so
  a client that signs a bare relay URL reaches a handler mounted at `/`.
  Empty `AllowedPubkeys` allows nobody. `VerifyAuthHeader` is unchanged. (#43)
- `nip86` carries NIP-86, the Relay Management API: the request/response
  shapes, the method names, and a `Router` that dispatches them. A request
  is selected by its `application/nostr+json+rpc` content type rather than
  a path, so the API shares the relay URL with the WebSocket upgrade and
  the NIP-11 document. The package is protocol only and does not import
  `relay/`, so binding the methods to a membership store stays with
  whatever composes the relay's handler. `Router.Visible` scopes which
  methods a caller sees, and a method hidden from a caller is also refused
  to it. `nip86.NewHandler` serves it over HTTP, including the CORS
  preflight a browser requires before it will send the request at all --
  neither the content type nor `Authorization` is CORS-safelisted, so
  without an answered `OPTIONS` an app cannot call the API. An empty origin
  allowlist answers any origin, which is safe when authorization is a signed
  header rather than a cookie. (#43)
- `huddle/room.Room.EvictPubkey` and `Manager.EvictPubkey` remove a pubkey
  from a live call, for a relay revoking a membership whose holder is
  mid-call: admission is checked once at join, so without it a removed
  member keeps hearing the room until it reconnects. Removal is the
  guarantee rather than the socket close -- a peer out of the registry is
  neither heard nor hearing -- and the room's other peers are untouched. (#43)
- `nipcash/client.BatchSession` fetches, verifies and caches a hub's
  kind-11190 announcement. The SDK had no way to obtain one --
  `ParseAnnouncement` only verifies an announcement a caller already holds --
  so four of the client obligations NIP-CASH places on a batching caller had
  no implementation path. The hub's key is required rather than discovered,
  and the announced inbox and relays are preferred over the token's hints.
  (#43)
- `nipcash/client` gains the batch API the private transport was built for:
  `RedeemMany`, `StatusMany`, `TransferMany` and `ConsolidateMany` act on many
  bills in one relay event instead of one event per bill. On the standard
  transport every request is p-tagged with a bill's own pubkey, so a holder
  consolidating fifty bills publishes fifty events that resolve to one, tying
  them together for anyone watching without decrypting anything. Batched, the
  count stops being public and the timing correlation disappears. (#43)
- A batch item has three outcomes, not two. A hub omits an item whose target
  it does not hold, whose proof did not verify, or whose method it does not
  serve, and those are indistinguishable by design -- telling them apart would
  make a batch an oracle for which bills a hub holds. `ItemOutcome` keeps "the
  hub said nothing" separate from "the hub refused", so a bill a hub simply
  does not hold is not reported as a failure of that bill, and
  `SafeToResend` says which spends a caller may retry. (#43)
- A hub may answer one request with several kind-23191 events sharing a
  `reply_to`, each carrying `seq` and `total`. A reply can be far larger than
  the request that produced it -- a `cash_status` item's params are 2 bytes
  while its answer for a 100-recipient bill is over 28 KiB -- so a hub could
  serve a batch and then be unable to report it, which for `cash_redeem` is
  money moved with the caller told nothing. A single-event reply is 1 of 1,
  filled in automatically. (#43)
- `cash_status` takes NIP-CASH's optional `scope`: `all` for the shared
  roster, `mine` for the caller's own row, defaulting to `mine` on the private
  transport and `all` on the standard one. Neither the field nor the default
  existed, so a private-transport caller who said nothing got every
  co-recipient's identity, amount and claim state -- the precise disclosure
  the private transport exists to prevent. (#43)
- `cash_status` carries an `AttestationEvent`, so a `connection_key` recipient
  can read their own row. That identity is a hash of platform and external id
  rather than a pubkey, so an item's signer can never equal it and a hub's
  gate had nothing to compare: the only options were to disclose the whole
  roster or to refuse that identity mode its only read. (#43)
- `mint_cash` takes an optional `idempotency_key`. It is the only
  value-creating method with no replay protection of its own -- a transfer or
  consolidate source carries a signed proof whose nonce the hub burns, while
  `mint_cash`'s params hold nothing unique -- so a caller whose retry logic
  reads a timeout as failure makes the hub mint and fund a second wallet. It
  does not make a lost reply re-readable, since a cash-mode mint's secret
  exists only in that reply; it prevents minting twice. Omitted when unset.
  (#43)
- `nip47.GetInfoResult.PrivateMethods` names the bill methods a hub serves
  only over the private transport. `methods` means callable here and those
  four are refused on kind 23194, so dropping them from `methods` was right
  but left no wire signal they exist at all, leaving a client to hardcode the
  set. Informational only -- authorization stays the hub's per-item check.
  (#43)
- `nipcash/transport` admits bearer items: a cash-mode credential authorizes
  with its secret rather than an item proof. Two of the four credential kinds
  hold no keypair, so requiring a kind-23192 proof per item shut them out of
  batching entirely -- and a bearer bill, whose life is otherwise a public
  timeline under one pubkey, is the one most in need of what batching hides.
  (#43)
- `transport.Envelope.Validate` rejects a proof bound to a different target,
  method, params or envelope than the item carrying it, and the item
  constructors derive every binding from a single source, so an incoherent
  item cannot be built in the first place rather than merely being caught.
  (#43)
- `relay.NewEventsHandler` serves POST /events: the write-side counterpart to
  `NewQueryHandler`'s POST /query, a NIP-98-authenticated HTTP bridge for
  submitting one already-signed event with no WebSocket connection open. A
  caller with only a /query-shaped relationship to the relay -- the buzz
  CLI, a reaction, a NIP-AM turn-metrics event -- previously had nowhere to
  publish at all. The NIP-98 signer must equal the submitted event's own
  pubkey (stricter than the WS EVENT path, which has no such blanket
  requirement, but every real caller already signs both with the same key),
  and NIP-43 join/leave requests are rejected outright, since
  `MembershipService.HandleEvent` needs a live `*Session` for its
  reply/broadcast side effects that an HTTP POST doesn't have. (#51)
- `examples/` holds runnable embedding patterns -- `basic-relay`,
  `full-relay`, and `relay-with-management-api`, the last mirroring how
  `ncli` composes the relay engine and the NIP-86 management API under one
  mux in production. README gets a matching "Embedding nmilat" section
  naming the three independent `http.Handler`s an embedder composes
  (relay, NIP-86, Huddle audio) and the performance guarantees that
  composition relies on. (#50)

### Changed

- `relay.RegisterLetteredNIP` now trims and upper-cases the id it is given,
  so `"b7"` and `"B7"` declare one NIP instead of two entries that both
  reach `supported_nips`. Every id this SDK registers was already
  upper-case, so nothing advertised changes. (#38)
- `relay.RegisterLetteredNIP` now panics on an id that cannot name a
  lettered NIP -- empty, containing anything but letters and digits, or all
  digits. It is called from `init()`, so the alternative was serving a
  malformed NIP-11 document for the life of the process. The all-digit case
  is the one that motivated this: `RegisterLetteredNIP("53")` compiled
  happily and advertised the JSON string `"53"` where every other
  implementation expects the number `53` -- use `RegisterNIP` for those. (#38)
- **The event store upgrades its indexes on first open, and the upgrade is
  one way.** A store written by this release cannot be read by an earlier
  one: the older binary misreads every index key, so writes appear to
  succeed while queries fail. Take a copy of the database file before
  starting this version. The rebuild runs at startup, before the relay
  accepts connections, and costs roughly a second per 20,000 stored events
  (2.3s for 50,000 on a development machine); progress is logged. (#37)
- **The relay now enforces NIP-70.** An event carrying `["-"]` is accepted
  only when its author has authenticated on that connection: unauthenticated
  gets `auth-required:`, authenticated as someone else gets `restricted:`.
  Previously a valid signature was enough, so anyone who had seen such an
  event could replay it -- for a NIP-43 join, burning the invite's remaining
  uses. Every NIP-43 kind carries the marker, so a client that publishes a
  join or leave must now AUTH first. `nip70.IsProtected` is the predicate,
  and NIP-11 advertises 70. (#43)
- **Bill methods now go through the `Client`, and the private transport is the
  only transport that serves them.** `Connect`, then call: `CashStatus`,
  `CashRedeem`, `CashTransfer` and `CashConsolidate` each run as a one-item
  batch, with the session opened on first use and the hub identity recovered
  from the bill's own mint signature. `cash_status` and `cash_consolidate`
  gained a credential argument, unavoidably: the standard transport authorized
  by connection, the private transport authorizes per item. A `Client` dialled
  with a bare pairing URI can still mint but cannot act on a bill, since such
  a URI carries no mint signature and so names no hub to verify an
  announcement against -- a real limit of a pairing URI, now stated outright
  instead of failing obscurely. (#43)
- **Mint provenance is mandatory**, so `MintSignature` is gone from
  `MintCashParams`, `CashTransferParams`, `CashConsolidateParams` and the
  client params that threaded it through. A token's mint signature is the only
  thing identifying its minting hub, and so the only thing a client can verify
  a transport announcement against -- a token without one could never reach
  the only transport that serves bill methods, making it unspendable. There
  was nothing to opt into. The `Token`'s own `MintSignature` and
  `AttestedAmountMillis` fields stay, and `VerifyProvenance` still reads them.
  (#43)
- `transport.WrapRequest` returns the conversation key. A reply is encrypted
  under a key derived from the request's ephemeral ECDH, which a hub can
  recompute from its own inbox key but a client cannot recover from anything
  on the wire -- the ephemeral private key must not be kept, because reusing
  it destroys the unlinkability it exists for. Without it every reply would
  have been undecryptable by the only party entitled to read it. (#43)
- An envelope may not repeat an identical request. A proof binds target, hub,
  method, params, nonce and expiry but not the item id, so one signed pair
  authorized any number of otherwise-identical items: 32 copies of a
  handed-over item all verify. No money followed, because every bill method
  carries its own idempotency guard, but those guards were the only line of
  defence and a fifth method added without one would inherit a
  duplicate-execution hole with no warning anywhere. (#43)
- An item id is capped at 256 bytes. `transport.Result` echoes the id back
  verbatim, so a request and its reply share one byte budget while the reply
  carries every id again plus the result bodies -- an id that fits going in
  need not fit coming back. A request filling a 56 KiB envelope with one
  48 KiB id owed a reply of 82 KiB, undeliverable for an item the hub had
  already served. The refusal deliberately does not quote the id. (#43)
- `RekeyCashSlice` takes the replacement target from its caller. It minted one
  itself, so the new secret lived only in a local variable while only a
  commitment crossed the wire: on any ambiguous error -- a timeout, or a hub
  lying about its chunk total -- the secret died with the stack frame while
  the hub may well have applied the re-key, leaving the slice redeemable only
  with a secret that existed nowhere and that the hub never had either. One
  dropped reply was enough. The caller can now write the secret down before
  the call and reconcile after, the only order that survives an ambiguous
  answer. (#43)
- **Every credential must name at least one usable relay**, enforced in the
  token codec and both hub-connection codecs, on encode and on decode. There
  is no discovery path behind a cash bill's wallet pubkey -- it is published
  nowhere, existing only as a subscription filter on the minting hub -- so a
  relay-less credential is permanently unusable while remaining structurally
  perfect. Usable means non-empty after trimming, which is the substantive
  part: a producer whose relay config was unset emits one empty-string relay
  rather than none, defeating every check that merely counts entries.
  Previously-decodable credentials now fail to decode; they could never have
  worked, so this moves a hang at dial time to a named error at decode time.
  (#43)
- `nip47`'s `circle_wallet` block renames `available_mloki` to
  `available_millis`, the last field on this wire still using the mloki
  vocabulary. No compatibility alias: a client reading the old name now gets a
  zero value and must be updated. The field is read once at discovery time to
  decide whether to join a circle, so an alias would be carried indefinitely
  to serve a single read. The unit is unchanged. (#43)
- `relay.PotentialEvent` now carries `Bytes`, the event's raw JSON as
  `collectBatch` found it at scan time. The REQ delivery loop
  (`handlers.go`) and the NIP-05 handler's consumer used to re-read each
  delivered event from the store -- `FindEventBytes`/`FindEvent`, each its
  own bolt read transaction -- right after the scan had already loaded the
  same bytes; they now use `Bytes` directly. Scanning and delivering 200
  matching events drops from 2.68ms to 1.77ms and 5270 to 3470 allocs/op
  (`BenchmarkDeliverREQ` vs. `BenchmarkDeliverREQLegacyPerEventStoreRead`,
  `relay/store_bench_test.go`). This also means an event deleted between
  scan and delivery is now delivered once anyway, using the bytes captured
  at scan time, rather than silently dropped -- a deliberate
  snapshot-consistency choice, not a live re-check. (#50)

### Fixed

- A filter's `limit` returned the oldest matching events instead of the
  newest. NIP-01 defines it as the last n events by `created_at`, but the
  query indexes were keyed by arrival sequence, so walking one backwards
  gave reverse insertion order rather than reverse time order. Separately,
  the per-cursor budget handed the whole limit to the first cursor, so a
  filter spanning several kinds, authors, tags or ids ignored recency
  altogether — and for tags the affected cursor varied between runs. Every
  index is now ordered by `created_at` and the cursors are merged by
  recency before the limit is applied. `COUNT` and NIP-77 reconciliation
  share the same path and are fixed with it. (#37)
- A `#<tag>` filter matched nothing when a longer tag value shared its
  prefix: `#h=1` returned no events once anything was tagged `h=10`. Tag
  index keys now carry the value's length. (#37)
- NIP-77 reconciliation could disagree with a peer over events sharing a
  timestamp. Items are now totally ordered by timestamp and id, as the
  negentropy implementation requires. (#37)
- Deleting an ephemeral event left its entry in the expiration index,
  because the insert and delete paths derived the retention window
  differently. (#37)
- A relay declaring NIP-57 rejected most real zap receipts. Sampling two
  public relays, 73% of kind-9735 events were refused at ingest: most
  because the embedded zap request carried a lightning address in its
  `lnurl` tag rather than the bech32 encoding, the rest over the invoice's
  description hash. NIP-57 makes the `lnurl` tag optional and matching it a
  SHOULD, and specifies no description-hash check for validating a receipt.
  A zap receipt is the record that a payment happened, so refusing one
  silently truncated zap totals, top-zapped ranking and
  `relay reindex --zaps`. Relays now store these receipts and still reject
  genuinely malformed ones. AltZap (NIP-AZ) is unaffected and stays
  stricter, as its spec requires. (#35)
- The `have=` and `want=` values reported in a description-hash mismatch
  were the wrong way round. `have=` is now the hash the invoice carries. (#35)
- A relay verified an event's signature before checking the proof-of-work
  floor, so an under-difficulty event still cost a signature verification.
  The floor is now enforced first, which is the cheaper check and the one
  that makes the PoW requirement worth declaring. (#39)
- NIP-59 gift wrapping assigned the sender's private key to the seal's
  `PubKey` field and relied on the following `Sign` call to overwrite it.
  Nothing leaked, because `Sign` does overwrite it — but the code was one
  reordering, or one seal built without signing, away from publishing a
  private key in a field designed to be public. `Sign` now owns that field
  outright. (#39)
- Neither the seal nor the gift wrap randomized `created_at`, so both
  carried the true time — the correlation signal wrapping exists to remove.
  Both now use `RandomizedCreatedAt` over NIP-59's two-day window. Two
  consequences follow for callers: a `since` filter will silently drop a
  fraction of legitimate wrapped events, and `created_at` is no longer
  evidence of freshness, so replay protection has to live inside the
  encrypted payload. (#39)
- `nipcw` read a circle join result from the wrong place, missing the fields
  the Hub returns under `encrypted_details`. (#39)
- `nip46.ParseNostrconnect` required a `metadata=` query param that NIP-46
  does not define, so it rejected every conforming `nostrconnect://` URI. The
  client's identity now comes from the spec's own `name`/`url`/`image` params,
  with the old blob still read as a fallback, and none of them are required.
  (#42)
- `ParseNostrconnect` read only the first `relay` param, so a client listing
  several got one — and pairing failed outright when that one was down. Every
  relay is kept now, in URI order, and an unusable entry is dropped rather
  than failing the whole URI. `NostrconnectSchema.Relays` carries them;
  `Relay` remains as a deprecated alias for the first. (#42)
- `ParseNostrconnect` discarded the `perms` list, leaving a signer no way to
  honor the permissions a client asked for. It is now kept verbatim in
  `NostrconnectSchema.Perms`. (#42)
- A schemeless relay host in a `nostrconnect://` URI is read as `wss://`
  rather than rejected. (#42)
- A tagless event's id was wrong. `MarshalTags` handed a nil tag slice
  straight to `encoding/json`, which renders it as `null`, and NIP-01's
  serialization is positional -- so the preimage carried `null` where every
  other implementation has `[]` and relays refused the event over an id
  mismatch. Signing and verifying inside this library agreed with each other,
  so nothing surfaced until the first event was published to a real relay.
  (#43)
- A batch reply subscription closed at EOSE, so every item in every batch read
  as omitted. EOSE ends stored events and a reply is always live: the hub has
  not seen the request when the subscription opens, and kind 23191 is
  ephemeral, so no relay stores it. (#43)
- `cash_status` could not carry a cash secret, so cash-mode bills never
  batched. The item was built with neither a proof nor a secret, which the
  codec's own rule refuses -- surfacing as "a single item exceeds the hub's
  envelope limit", the wrong error for an item that is malformed rather than
  oversized. (#43)
- A nil proof marshalled to `"proof":null` instead of being omitted, and
  decoding that literal yields four bytes, so every proofless item arrived
  looking like it carried a proof. A cash-mode bill is proofless by design, so
  the hub took the proof branch, failed to verify `null`, and omitted the item
  -- and omission is information-free by design, so this surfaced only as "no
  cash-mode bill works over the private transport". (#43)
- Four defects a hostile hub or relay could exploit. A lying chunk `total`
  made the SDK discard a real success, so a completed carve -- source bill
  drained, funds in a new wallet whose token existed only in that reply --
  was returned to the caller as a failure, and the same lie erases the
  `cash_status` that is the prescribed recovery call. A decided outcome now
  beats a send error. Nothing compared a hub announcement's `created_at`
  against the one already held, so a relay could replay the hub's own retired
  policy and walk a session backwards onto a padding bucket that leaks the
  batch count; adoption now keeps the newest candidate and never moves
  backwards. An announced `pad_bucket_bytes` had no floor, so announcing 1
  gave eight distinct wire sizes for one to eight items; `ValidateAnnounced`
  gates what is safe to adopt from a hub, separately from whether a locally
  built policy is coherent. And two chunks could answer the same item id with
  arrival order deciding which contradictory answer won, letting a relay that
  holds no key choose whether the client believes `NOT_FOUND` or a live bill;
  a cross-chunk duplicate is now refused in either order. (#43)
- An envelope-level refusal was collected and never read. A hub answering
  envelope-level `RATE_LIMITED` means no item ran, which is exactly what a
  caller needs before resending a `cash_redeem`, and dropping it left every
  item merely not-served -- whose contract is the opposite, indistinguishable
  from an item that executed and whose response was lost. A hub could strand a
  caller in permanent indeterminacy having done nothing at all. It is now
  surfaced per item as a decided error, where callers already look. (#43)
- Collecting a reply had no deadline of its own, so a hub declaring `total: 2`
  and sending one chunk left a client waiting out its entire deadline for a
  reply that will never come, even when the envelope expired minutes earlier.
  The wait is now bounded by the envelope's own `not_after`, the value both
  sides already agreed on and signed; a caller with a shorter deadline still
  wins. (#43)
- `relay/client.NewNWCClient` dialled only the first relay hint and silently
  ignored the rest, so a credential naming three relays was a single point of
  failure with two decoys -- an operator who configured three had done the
  thing that looks like redundancy and got none. Each hint is now tried in
  order until one connects, unparseable entries are skipped rather than fatal,
  and when nothing can be reached the error names every attempt. This matters
  more here than for an ordinary client because a cash bill is a bearer
  instrument whose holder cannot be handed a corrected string, so a dead relay
  takes the bill with it unless the others are tried. (#43)
- `nip98.Verify`'s generic proof-of-work check triggered on any tag literally
  named `nonce` (`nip13.POWTagName`), regardless of event kind or tag shape.
  A client-side anti-replay nonce -- buzz-acp's 2-element
  `["nonce", <uuid>]`, unrelated to NIP-13's 3-element
  `["nonce", <hex>, <difficulty>]` -- collided on tag name alone and failed
  PoW validation, rejecting an otherwise fully valid, correctly-signed
  NIP-98 HTTP-auth event with a generic "invalid NIP-98 event payload"
  error. PoW checking is now skipped for NIP-98's own auth wrapper via the
  existing `WithoutPowCheck` option: proof-of-work belongs to events
  actually being stored, never to the ephemeral header around a request.
  (#51)
- POST /query ignored its own `Limit` field entirely. `FindEvents` (the
  handler's only caller) scanned every matching event to exhaustion
  regardless of what the client requested -- the one reader of this scan
  not to pass `scan.fetch`'s `fetchUntilEmpty` as `false`, unlike REQ's own
  replay and `handler_nip05.go`. Fixed alongside a second, independent bug
  it had been masking: `eventQueue`'s heap had no tie-break beyond
  `CreatedAt`, so same-second events had no stable order at all -- which is
  what made NIP-CW's composite cursor (`Until`+`BeforeID`) unable to
  terminate pagination across a same-second burst. In production,
  buzz-acp's `query_raw_all` would loop until its own 10,000-event safety
  cap tripped, burning thousands of wasted round trips before failing.
  `BeforeID` is now a recognized filter field, resolved once per scan to
  its own `evsid` (most indexes' keys don't carry the 32-byte event id at
  all, but `evsid` is common to every one of them), and the heap
  tie-breaks by `Evsid` descending. (#52)

## [0.4.0]

### Breaking

- NIP-CASH's "bearer" mode is now called **cash mode**, on the wire and in
  the Go API (#30). Slices with no registered identity send
  `identity_type: "cash"` instead of `"bearer"`, and their secret travels
  as `cash_secret` instead of `bearer_secret`. The `new_identity_hash`
  bound into a transfer or consolidate proof for such a target is now
  computed over `"cash:" + commitment + ":"`. This release only works
  with a Hub that speaks the renamed protocol (lokihub 0.5.0-rc.6 or
  later); older Hubs reject its cash-mode requests, and older nmilat
  releases don't work against the renamed Hub. Existing tokens and
  `<token>#<secret>` strings are unaffected.
- Renamed Go identifiers, with no deprecated aliases:

  | Before | After |
  |---|---|
  | `nipcash.BearerTarget`, `nipcash.NewBearerTarget` | `nipcash.CashTarget`, `nipcash.NewCashTarget` |
  | `.BearerSecret` on `RecipientResult`, `CashRedeemRequest`, `CashTransferRequest` | `.CashSecret` |
  | `RecipientStatus.IsBearer()`, `CheckClaimResult.IsBearer` | `RecipientStatus.IsCash()`, `CheckClaimResult.IsCash` |
  | `nipcash.ErrMixedBearerAllocation`, `nipcash.ErrBearerSource` | `nipcash.ErrMixedCashAllocation`, `nipcash.ErrCashSource` |
  | `nipcash.SplitBearerSliceString` | `nipcash.SplitCashSliceString` |
  | `client.RekeyBearerSlice`, `RekeyBearerSliceParams`, `RekeyBearerSliceResult` | `client.RekeyCashSlice`, `RekeyCashSliceParams`, `RekeyCashSliceResult` |
  | `RekeyBearerSliceParams.BearerSlice` | `RekeyCashSliceParams.CashSlice` |

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
