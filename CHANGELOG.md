# Changelog

## [0.5.0]

NIP-CASH's private transport, NIP-29 groups hosted by the relay, huddle audio,
NIP-86 relay management and HTTP bridges, and a long run of relay access,
privacy and performance fixes.

### Added

- Adds `nip44.MessageKeys` and `nip44.OpenWithKeys`: one payload's message
  keys, MAC checked, which open that payload and no other. The package now
  tests against the official NIP-44 v2 vectors.
- Adds the `nip44_message_keys` method to `nipLS` and `nip46/bunker` (server
  and client), and `nipLS.ResultPolicy`, which sees an encrypt or decrypt
  result before it is returned.
- Adds `nip59.Seal`, `WrapSeal` and `Unwrap`, which take the key as a signer
  and never open a seal from a sender not asked for. `Prove` and
  `VerifyProof` show one seal's content to a third party without any key.
- Adds `WithSearchBatch` and `WithSearchInFlight`: `SearchIndexer` keeps
  several batches enqueued with a `search.Enqueuer` engine and acknowledges
  them in order, only past what was applied. A large relay's search can then
  keep up, since the engine merges queued batches.
  ([#179](https://github.com/ohstr/nmilat/pull/179))
- Adds `EventStore.EachProfile`: every author's newest profile, read through
  the kind index instead of every stored event, so a search rebuild reads
  only profiles.
  ([#179](https://github.com/ohstr/nmilat/pull/179))
- Adds `EventStore.IndexStatus`: each derived index's state (`ready`,
  `behind`, `needs_rebuild`, ...), the action that brings it current and why,
  its exact entries, and a paused rebuild's position.
  ([#173](https://github.com/ohstr/nmilat/pull/173))
- Adds `RebuildIndex` (resumes where a restart stopped it), `CatchUpIndex`,
  `RescoreIndex`, `ClearIndex`, `ReapIndex` and `RunIndexAction`;
  `WithEventStoreIndexMaintenance(MaintenanceManual)` leaves running them to
  the embedder.
  ([#173](https://github.com/ohstr/nmilat/pull/173))
- Adds durable feeds (`WithEventStoreFeeds`, `FeedChanges`, `AckFeed`,
  `FeedStatus`) and `SearchIndexer`, which keeps a search engine in step with
  stored profiles, their deletions and score changes.
  ([#173](https://github.com/ohstr/nmilat/pull/173))
- Adds `StoreObserver.IndexBatchCommitted`, one call per index operation
  transaction.
  ([#173](https://github.com/ohstr/nmilat/pull/173))
- Adds the `zap-ranking` cache action: receivers ranked by counted zaps in
  one coin over one window, as a relay-signed kind 25521 tagged `window`,
  `coin` and `limit`. `SessionConfig.Zaps` lists the windows (`all` is all
  time) and coins a request may name; the first of each is the default and
  `limit` is capped at `MaxLimit`. Lists are computed together in one pass on
  first use, reused for `Refresh`, served stale while one refresh runs,
  skipped when nothing was written and dropped when idle.
  ([#167](https://github.com/ohstr/nmilat/pull/167))
- Adds each zap's coin (`Coin`: sats from a `bc`/`tb`/`tbs`/`bcrt` invoice,
  loki from `fc`, else a 9521's `chain` tag) to the zap and social indexes.
  A store from before rebuilds both once in the background on open.
  ([#167](https://github.com/ohstr/nmilat/pull/167))
- Adds `zap_amt_recd_<coin>`/`zap_amt_sent_<coin>` NIP-85 tags for each
  configured coin besides sats with an amount, and `ProfileStats.AmtRecd`/
  `AmtSent` per coin.
  ([#167](https://github.com/ohstr/nmilat/pull/167))
- Adds exact counters of stored events per kind and distinct authors, kept
  in the same transaction as the indexes (`EventStore.Counts`); an older
  store is counted in the background in short write transactions.
  ([#167](https://github.com/ohstr/nmilat/pull/167))
- Adds `RelayDiscovery` and `EventStore.PublishSelfSigned`, to publish the
  relay's own NIP-66 kind 30166 (counts, zap totals, supported NIPs,
  requirements), stored only when something changed.
  ([#167](https://github.com/ohstr/nmilat/pull/167))
- Adds `EventStore.ZapTotals`, `TopZapped` (one window and coin, uncached)
  and `Commits`, `utils.ParseDuration` (`s`, `m`, `h`, `d`, `w`, `mo`) and
  the `nip57/nip57test` package, which builds valid 9735 and 9521 receipts
  in either coin for tests.
  ([#167](https://github.com/ohstr/nmilat/pull/167))
- Adds NIP-85 user assertions: with `SessionConfig.EnableProfileStats`, a REQ
  for kind 30382 with `#d` pubkeys gets relay-signed stats (rank, followers,
  following, zaps received/sent with first and last time, verified
  NIP-05/lightning address), and NIP-11 lists 85.
  ([#165](https://github.com/ohstr/nmilat/pull/165))
- Adds followers and received zaps to a profile's search score: each sender
  adds a capped amount, scaled by their own profile score, so many throwaway
  keys or a self-run LNURL server add little. Weights live in `search.social`.
  ([#165](https://github.com/ohstr/nmilat/pull/165))
- Adds `EventStore.GetProfileStats`: a profile's zaps received and sent (count,
  amount, distinct zappers, first and last time) and follower/following counts,
  from an index kept current on every write and built once on first start.
  ([#165](https://github.com/ohstr/nmilat/pull/165))
- Adds `config.Configure`, so an embedder can set its own scoring weights.
  ([#164](https://github.com/ohstr/nmilat/pull/164))
- Adds `ProfileMetrics.CheckScore`, which rescores a profile from its stored
  check results with the current weights, without fetching anything.
  ([#164](https://github.com/ohstr/nmilat/pull/164))
- Adds `nip47.CircleWalletInfo.PerWalletMaxMillis` and `MinBudgetRenewal`, a
  Hub's per-wallet ceiling and budget-renewal floor from NIP-CW `get_info`, so a
  client can check a join before sending it.
  ([#159](https://github.com/ohstr/nmilat/pull/159))
- Adds `nipcw/client.ErrJoinNotSent`, which marks a `Join` that failed before
  anything was sent, so a caller can tell it from one whose outcome is unknown.
  ([#157](https://github.com/ohstr/nmilat/pull/157))
- Adds `nip47.CircleWalletInfo.Identity`, the node key a Hub reports in
  `get_info` when it offers NIP-CW Private Join, and the `circle_policy`
  constants `CirclePolicyAllowlist` and `CirclePolicyFollowSet`.
  ([#146](https://github.com/ohstr/nmilat/pull/146))
- Adds `nipcw/client.Client.Join`, which joins a circle over NIP-CASH's private
  transport when the Hub offers it, so the join is not visible on the shared
  Hub connection; a fallback to the standard transport is reported, never silent.
  ([#146](https://github.com/ohstr/nmilat/pull/146))
- Adds `utils.ParsePrivateKeyHex`, which decodes a hex secret key and refuses
  one outside [1, n-1].
  ([#141](https://github.com/ohstr/nmilat/pull/141))
- Adds `nip11.Metadata.Banner`, NIP-11's "banner" image URL, settable from
  config as `banner`.
  ([#132](https://github.com/ohstr/nmilat/pull/132))
- Adds `EventStore.RebuildZapIndex`, which rebuilds the zap index beside the
  live one and swaps it in atomically, so top-zapped results never go empty
  during a rebuild.
  ([#131](https://github.com/ohstr/nmilat/pull/131))
- Adds queue-depth and drop counters for profile verification and search
  indexing, `MembershipService.Count`, `GroupsService.Count`, and
  `EventStore.TaskQueueDepth`/`InflightScans`, so an embedder can graph them.
  ([#131](https://github.com/ohstr/nmilat/pull/131))
- Adds `relay.Observer` and `StoreObserver` (`WithObserver`,
  `WithEventStoreObserver`) for relay metrics: sessions, messages, EVENT
  outcomes by reason and kind class, REQ/COUNT latency, subscriptions, AUTH,
  sends and store batches, without allocating on the hot path.
  ([#131](https://github.com/ohstr/nmilat/pull/131))
- Adds `MaxAmountMillis` to `nipcw.CreateCircleWalletResponse`, the spend cap
  as the Hub resolved it, and the refusal codes `nipcw.ErrNotReady`,
  `ErrRestricted`, `ErrWalletExists` and `ErrRateLimited`, as NIP-CW now specifies.
  ([#123](https://github.com/ohstr/nmilat/pull/123))
- Adds `nipAZ.ValidateAltZapRequestForRelay`/`ValidateAltZapReceiptForRelay`,
  which `nipAZ/relayreg` now uses: relays keep receipts for real payments and
  reject only forged AltZap events, as NIP-AZ specifies.
  ([#118](https://github.com/ohstr/nmilat/pull/118))
- Adds `NWCClient.Notifications`, which delivers a wallet's NIP-47 payment
  notifications as they arrive, and `NWCClient.Done`, which tells a
  long-lived holder when to reconnect. ([#116](https://github.com/ohstr/nmilat/pull/116))
- Adds `utils.RequestPayInvoice` for any LNURL-pay callback (LUD-12 comments
  included) and `Tag`, `CommentAllowed`, `Metadata` on `utils.PayResponse`.
  ([#116](https://github.com/ohstr/nmilat/pull/116))
- Adds `nip98.NewAuthHeader`, `utils.ResolveNip05`, and hex-key
  `nip44.EncryptHex`/`DecryptHex`. ([#116](https://github.com/ohstr/nmilat/pull/116))
- Adds the invoice memo and currency prefix to `nip57.Invoice`
  (`Description`, `Currency`). ([#116](https://github.com/ohstr/nmilat/pull/116))
- Adds `WithRequestHandler`, REQ handlers run ahead of the built-in ones, and
  `Session.SendEvents`/`SendEOSE` to answer a REQ in the handler's own order, so
  an embedder can serve NIP-50 search from its own index, best match first.
  ([#111](https://github.com/ohstr/nmilat/pull/111))
- Adds `nip11.Metadata.Icon`, NIP-11's `icon` URL, settable as `nip11.icon`.
  ([#106](https://github.com/ohstr/nmilat/pull/106))
- Adds `SessionConfig.EventPolicy` and `WithEventsPolicy`, a hook that can refuse
  any event after validation, over the WebSocket and `POST /events`, so an
  embedder can enforce its own bans and kind rules.
  ([#106](https://github.com/ohstr/nmilat/pull/106))
- Adds optional pending NIP-29 join requests: with `GroupsService.SetPendingJoins(true)`
  a closed group keeps a join request without an invite code for its admins,
  who accept with kind 9000 or decline with 9001.
  ([#105](https://github.com/ohstr/nmilat/pull/105))
- Adds an optional NIP-29 moderation log: with `GroupsService.SetModerationLog(true)`
  accepted moderation events are stored and readable by the group's members
  (invites by its admins), so clients can show who did what.
  ([#104](https://github.com/ohstr/nmilat/pull/104))
- Adds kind 39003 group roles: the relay publishes one per NIP-29 group from its
  moderation policy, and republishes them when the policy changes, so clients
  know which roles exist. `GroupsService.SetRoleDescriptions` describes them.
  ([#103](https://github.com/ohstr/nmilat/pull/103))
- Adds `RelayStatus.LastEOSE`, when a relay last finished a complete sync, and
  `RelayStatus.Closed`, the relay's reason when it closed the pool's subscription.
  ([#91](https://github.com/ohstr/nmilat/pull/91))
- Adds `nip19.ParsePublicKey`, which reads an npub, nprofile or hex public key
  and rejects an nsec, a wrong length or a point off the curve.
  ([#91](https://github.com/ohstr/nmilat/pull/91))
- Adds `nip46/bunker` for NIP-46 signing over relays: `Dial`
  (`bunker://`), `NewPairing` (`nostrconnect://`) and `Resume` for clients,
  and `NewServer`, with a policy per request, for signers. ([#85](https://github.com/ohstr/nmilat/pull/85))
- Adds `nipLS` for signing through a local signer over a unix socket
  (`bunker+unix:///path.sock`): `Dial` for clients, `NewServer` to serve a
  key behind your own policy. ([#83](https://github.com/ohstr/nmilat/pull/83))
- Adds `nip46.Signer` and `nip46.LocalKey`, one signing interface that a
  local key, a socket client and a bunker client all implement.
  ([#85](https://github.com/ohstr/nmilat/pull/85))
- Adds NIP-42 authentication through a signer (`ConnectionConfig.Signer`,
  `ReadEventsFromRelayWithSigner`), so a key behind a bunker or socket
  signer can authenticate. ([#87](https://github.com/ohstr/nmilat/pull/87))
- Adds `relay/client.Pool`, a subscription per relay that survives
  reconnects, with optional resync and de-duplication. ([#87](https://github.com/ohstr/nmilat/pull/87))
- Adds `ReadAllEventsFromRelay`, which pages a query to its end without
  skipping events that share a second. ([#87](https://github.com/ohstr/nmilat/pull/87))
- Adds `nip01.LatestVersion`, which picks the winning version of a
  replaceable or addressable event the way the relay store does, ignoring
  future-dated ones. ([#87](https://github.com/ohstr/nmilat/pull/87))
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

- Changes a derived index that missed writes while off to catch up from
  where it stopped instead of rebuilding. Too many deletes meanwhile, a
  layout change or writes by another program still mean a rebuild.
  ([#173](https://github.com/ohstr/nmilat/pull/173))
- Changes index operations to hold the writer at most 25 ms or 256 events
  per transaction; a swap or clear only moves a pointer and the old data is
  freed in chunks.
  ([#173](https://github.com/ohstr/nmilat/pull/173))
- Changes search indexing and profile checks to follow stored profiles
  through feeds instead of the EVENT path, so none is lost to a full queue, a
  restart or the feature being off. `search.Searcher` and `search.Writer`
  replace `search.Service`, `ServiceImpl` and `ReadOnlyService`.
  ([#173](https://github.com/ohstr/nmilat/pull/173))
- Changes the social score queue and a rescore's position to be kept in the
  store; a change to `search.social` rescores every profile.
  ([#173](https://github.com/ohstr/nmilat/pull/173))
- Removes `RebuildZapIndex`, `ReindexZaps`, `ClearZapIndex`,
  `RebuildSocialIndex`, `ClearSocialIndex`, `ZapIndexState`,
  `SocialIndexState`, `TakeSocialRescore`, `ProfileVerificationWorker.QueueJob`
  and `TotalDropped`, in favour of the calls above.
  ([#173](https://github.com/ohstr/nmilat/pull/173))
- Changes the zap and social indexes to opt-in with `WithEventStoreIndexes`:
  a store opened without one neither writes nor rebuilds it, and its readers
  return `ErrIndexDisabled`. A disabled index keeps its data, marked stale
  by the first write it misses and rebuilt in the background once enabled
  again (`ZapIndexState`/`SocialIndexState` report it).
  ([#171](https://github.com/ohstr/nmilat/pull/171))
- Changes NIP-45 COUNT: a filter of only `kinds` (or nothing) is answered
  exactly from the counters, past `max_limit`, without a scan; any other
  filter that stops at its limit answers `"approximate": true`.
  ([#167](https://github.com/ohstr/nmilat/pull/167))
- Changes the social score to count received sats only; zaps in other coins
  still count toward `zap_cnt_*` and zappers.
  ([#167](https://github.com/ohstr/nmilat/pull/167))
- Removes the `top-zapped`/`get_top_zapped` cache action,
  `GetTopZapped`/`ZapStats`, `SessionConfig.EnableTopZapped`,
  `DefaultCacheWindow`/`DefaultCacheLimit`, `WithSessionTopZapped` and
  `WithSessionCacheConfig`; use `zap-ranking` and `SessionConfig.Zaps`.
  ([#167](https://github.com/ohstr/nmilat/pull/167))
- Changes profile verification to check a profile's `lud06` LNURL when it has
  no `lud16`, so older profiles get their lightning address verified too.
  ([#165](https://github.com/ohstr/nmilat/pull/165))
- Changes profile verification to fetch only for a new or changed identifier,
  an expired result, a retry or `VerifyNow`, rate-limited per host;
  `SessionConfig.Verification` sets the TTL, backoff and limits, and the unused
  `verification_ttl_hours` and `default_predefined_bonus` settings are removed.
  ([#164](https://github.com/ohstr/nmilat/pull/164))
- Logs session open/close, AUTH, rejected events and refused WebSocket
  upgrades at debug instead of info/warn/error, and rate-limits slow/failed
  write warnings. A busy relay no longer floods its log, and clients can no
  longer write error lines at will.
  ([#148](https://github.com/ohstr/nmilat/pull/148))
- Logs a write to a client that already hung up (broken pipe, connection
  reset) at debug instead of warn/error, and only once per close. Ordinary
  disconnects no longer look like relay faults.
  ([#153](https://github.com/ohstr/nmilat/pull/153))
- Changes `create_circle_wallet` to the member-generated connection key NIP-CW
  now specifies: the client sends only `connection_pubkey` (new
  `nipcw.ConnectionKey`, bound by a `connection` tag in the identity proof) and
  builds `PairingURI` itself from the Hub's `wallet_pubkey` and `relays`. The
  Hub-generated secret is gone, so Hubs must implement the new join.
  ([#127](https://github.com/ohstr/nmilat/pull/127))
- Changes the NIP-CASH params hash (`transport.CanonicalParamsHash`) to write
  strings as RFC 8785 does, so `<`, `>`, `&`, U+2028 and U+2029 are no longer
  escaped. Params containing them hash differently from earlier releases, so
  clients and Hubs must upgrade together.
  ([#123](https://github.com/ohstr/nmilat/pull/123))
- Moves `nipAZ` to NIP-AZ's new kinds: 9520 requests, 9521 receipts, 9523
  on-behalf requests. Events of the old kinds 5520, 5521 and 5523 are no longer
  parsed, validated or indexed. ([#114](https://github.com/ohstr/nmilat/pull/114))
- Removes `nipAZ`'s kind 5522 direct payment (`NewAltZapDirectPaymentRequest`,
  `KindAltZapDirectPayment`), which NIP-AZ does not define.
  ([#114](https://github.com/ohstr/nmilat/pull/114))
- Enforces NIP-AZ's sender and settlement rules: a 9520 request must not carry
  `P`, a 9523 carries exactly one, and a receipt's chain and preimage must match
  its request and invoice. ([#116](https://github.com/ohstr/nmilat/pull/116))
- Pages each filter of a `Pool` subscription to its end on connect and on
  resync, so a relay's result cap no longer cuts it short (`PoolConfig.PageSize`).
  ([#91](https://github.com/ohstr/nmilat/pull/91))
- Moves `ReadEventsFromStore` from `relay/client` to `relay`, so `relay/client`
  and `nip46/bunker` no longer pull in bbolt and yaml. ([#91](https://github.com/ohstr/nmilat/pull/91))
- Requires Go 1.26.10 for its standard-library security fixes.
  ([#89](https://github.com/ohstr/nmilat/pull/89), [#161](https://github.com/ohstr/nmilat/pull/161))
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

- Fixes a filter with several tag names walking every tag's index range, so
  `#d` lookups plus a common tag such as `#l` took seconds. The scan now
  follows the smallest range and checks the other tags per event.
  ([#177](https://github.com/ohstr/nmilat/pull/177))
- Fixes a REQ failing with `event not found` when a matching event was
  deleted or replaced while its scan ran.
  ([#177](https://github.com/ohstr/nmilat/pull/177))
- Fixes an index rebuild or catch-up panicking (index out of range [-1]), and
  freeing old index data spinning without progress, when waiting for a busy
  store's writer took longer than the 25 ms batch budget.
  ([#175](https://github.com/ohstr/nmilat/pull/175))
- Fixes a rebuild putting back an event deleted while it ran.
  ([#173](https://github.com/ohstr/nmilat/pull/173))
- Fixes a contact list losing the follows it shares with an older one
  removed after it.
  ([#173](https://github.com/ohstr/nmilat/pull/173))
- Fixes a profile the store rejected as older still reaching search.
  ([#173](https://github.com/ohstr/nmilat/pull/173))
- Fixes follower counts doubling when a contact list and its replacement
  were written in the same batch.
  ([#171](https://github.com/ohstr/nmilat/pull/171))
- Fixes `ClearZapIndex`/`ClearSocialIndex` leaving the index marked current
  and racing a running rebuild. They now refuse during one, and work on a
  disabled index.
  ([#171](https://github.com/ohstr/nmilat/pull/171))
- Fixes social scores staying stale after a social index rebuild; every
  profile is rescored in the background.
  ([#171](https://github.com/ohstr/nmilat/pull/171))
- Fixes a crashed rebuild's leftover generation receiving every later write;
  it is dropped on open.
  ([#171](https://github.com/ohstr/nmilat/pull/171))
- Fixes a NIP-77 sync with a large diff sending one message of several MB,
  which strfry and most relays drop mid-sync. Messages now stop at
  `Negentropy.FrameSizeLimit` (30 000 bytes by default) and the rest follows
  in later rounds, split and encoded as the reference negentropy does.
  ([#169](https://github.com/ohstr/nmilat/pull/169))
- Fixes zap amounts in different coins being added together in the zap
  ranking, NIP-85 `zap_amt_*` and the social score.
  ([#167](https://github.com/ohstr/nmilat/pull/167))
- Fixes an unknown cache action falling through to a REQ with an empty
  filter, which streamed the whole store; it's `CLOSED "invalid: unknown
  cache action ..."`. A ranking window like `7d` was also read with Go's
  duration parser and silently became the default.
  ([#167](https://github.com/ohstr/nmilat/pull/167))
- Fixes a panic in a profile check killing the relay: each check and each
  verification job now recovers, logs the panic and counts the check as a
  transient failure. ([#166](https://github.com/ohstr/nmilat/pull/166))
- Fixes a REQ with a malformed `ids` or `authors` value being logged at error
  and answered `CLOSED "error: ..."`; it's now `CLOSED "invalid: ..."`, logged
  at debug. A client going over `max_message_length` or resetting the
  connection is no longer logged as an unexpected session error. ([#166](https://github.com/ohstr/nmilat/pull/166))
- Fixes top-zapped counting invalid receipts, self-zaps, duplicate receipts of
  one payment and deleted receipts; once a recipient's LNURL server key is
  verified, only receipts that server signed count.
  ([#165](https://github.com/ohstr/nmilat/pull/165))
- Fixes the gibberish-name search penalty hitting names written in non-Latin
  scripts. ([#164](https://github.com/ohstr/nmilat/pull/164))
- Fixes search scores dropping a profile's base score once its checks ran, and
  counting a picture twice; a broken picture now takes its bonus back.
  ([#164](https://github.com/ohstr/nmilat/pull/164))
- Fixes profiles shown as having no NIP-05 or lightning address when they do:
  identifiers with TLDs longer than four letters are checked now, and a
  timeout, block or 5xx keeps the previous result and is retried instead of
  counting as "not verified" for two weeks.
  ([#164](https://github.com/ohstr/nmilat/pull/164))
- Fixes a data race when two connections open at once on a relay whose
  `SessionConfig` leaves `OutgoingBufferSize` or `MaxConcurrentStoreTasks` at
  zero: each session now fills those defaults on its own copy instead of
  writing them into the config every session shares.
  ([#162](https://github.com/ohstr/nmilat/pull/162))
- Fixes NIP-50 search results coming back newest profile first instead of
  best match first, and `limit` keeping the most recently updated profiles;
  results now follow the search ranking, with `limit` applied after it.
  ([#155](https://github.com/ohstr/nmilat/pull/155))
- Fixes `nipcw/client.Client.Join` hiding why a join was not private when the
  standard join fails after a fallback; `errors.Is` now finds the fallback
  reason, such as `cashclient.ErrNoAnnouncement`, as well as the refusal.
  ([#151](https://github.com/ohstr/nmilat/pull/151))
- Fixes `NWCClient` accepting a response signed by any key, so anyone on the
  relay could answer a request with a forged result; responses must now come
  from the wallet's pubkey and carry a valid signature.
  ([#138](https://github.com/ohstr/nmilat/pull/138))
- Fixes `nip44.Encrypt` sealing an empty plaintext no peer can open and
  wrapping the length of one above 65535 bytes; it now follows NIP-44's current
  rules, 1 byte to 4 GiB with a 6-byte length prefix from 65536 bytes on.
  ([#139](https://github.com/ohstr/nmilat/pull/139))
- Fixes the BOLT11 decoder wrapping an amount too large for int64 millis into a
  different, sometimes negative, amount; such an invoice is now refused.
  ([#140](https://github.com/ohstr/nmilat/pull/140))
- Fixes a secret key of 0 or at or above the curve order being reduced into a
  meaningless key; `GetPublicKey`, `Event.Sign` and every encrypt, sign and
  proof path now refuse it with `utils.ErrInvalidPrivateKey`.
  ([#141](https://github.com/ohstr/nmilat/pull/141))
- Fixes event ids for tags containing U+2028 or U+2029 differing from every
  other client, so a relay or Hub on nmilat no longer rejects such an event
  signed elsewhere; tags are now escaped exactly like the content.
  ([#142](https://github.com/ohstr/nmilat/pull/142))
- Fixes `nip04.Decrypt` panicking on a ciphertext that is not a whole number
  of AES blocks, so one malformed payload could crash the caller; it now
  returns an error. ([#144](https://github.com/ohstr/nmilat/pull/144))
- Fixes `ReindexZaps` skipping NIP-57 zap receipts (kind 9735), so a rebuilt
  zap index no longer drops them from top-zapped results.
  ([#131](https://github.com/ohstr/nmilat/pull/131))
- Fixes the NIP-CASH private transport listening for a reply on a different
  relay than the one the request was sent to, and treating a relay's refusal
  of the request as sent; a reply chunk delivered by two relays now counts
  once instead of voiding the reply.
  ([#128](https://github.com/ohstr/nmilat/pull/128))
- Fixes the NIP-CASH private transport sometimes losing a reply when the
  request reached the relay before the reply subscription; it now waits for the
  relay's EOSE before sending. ([#129](https://github.com/ohstr/nmilat/pull/129))
- Fixes NIP-CASH request builders accepting what the spec forbids: an empty
  `mint_cash`, a `connection_key` without `ia_pubkey`, a negative or sub-second
  expiry, duplicate consolidate sources, and a nil transfer target (which
  panicked) now return errors. ([#125](https://github.com/ohstr/nmilat/pull/125))
- Fixes `ItemOutcome.SafeToResend` saying yes for a Hub success the client
  could not decode; such an item ran, so it is now marked `Undecodable` and not
  safe to resend. ([#125](https://github.com/ohstr/nmilat/pull/125))
- Fixes `BatchSession`'s `*Many` methods sending a bill minted by another node,
  which the Hub can only answer with silence; such a bill is now refused locally.
  ([#125](https://github.com/ohstr/nmilat/pull/125))
- Fixes the NIP-CASH private transport reporting only the last relay's failure
  when none could be reached; the error now names every relay it tried.
  ([#125](https://github.com/ohstr/nmilat/pull/125))
- Fixes `nipcash.VerifyProvenance` checking every token under flnd's
  signing prefix: a `satscash1` token now verifies under lnd's, and an HRP
  with no known prefix reports no provenance instead of a wrong minter.
  ([#121](https://github.com/ohstr/nmilat/pull/121))
- Fixes `CheckClaim` reporting a spent bill as `ErrClaimNotFound`: a Hub's
  tombstone now returns the new `nipcash.ErrSpent`, so a caller can tell
  "spent" from "this token does not name you".
  ([#121](https://github.com/ohstr/nmilat/pull/121))
- Fixes `CashConsolidate` returning the still-encrypted token as
  `NewWalletToken` when the delivery could not be decrypted; it now returns an
  error, as `CashTransfer` does. ([#121](https://github.com/ohstr/nmilat/pull/121))
- Fixes `transport.Decode` rejecting a whole envelope over one malformed item:
  it now drops that item into the new `Envelope.Rejected` and keeps its
  co-items, since NIP-CASH authorizes each item on its own.
  ([#121](https://github.com/ohstr/nmilat/pull/121))
- Fixes chunked NIP-CASH replies read as incomplete or thrown away: the client
  bounds a Hub's `total` by the items it asked for, keeps earlier chunks when a
  later one is malformed, and returns a Hub's refusal ahead of "incomplete".
  ([#121](https://github.com/ohstr/nmilat/pull/121))
- Fixes the cash token, `cashhub1` and `circlehub1` encoders writing a blank
  relay entry that sat beside a real one; blank entries are now skipped.
  ([#121](https://github.com/ohstr/nmilat/pull/121))
- Fixes `nipAZ.NewAltZapOnBehalfRequest`, whose events never verified because
  they were signed before their kind was set to 9523.
  ([#116](https://github.com/ohstr/nmilat/pull/116))
- Fixes deleting a NIP-29 subgroup: it now leaves its parent's `child` list,
  and an edit to the parent drops ids that no longer exist, so a stale child no
  longer breaks reads of the parent's subgroups.
  ([#109](https://github.com/ohstr/nmilat/pull/109))
- Fixes NIP-29 edits that flip `private` on a linked group: one whose parent
  or a subgroup would end up with the other setting is now refused, as linking
  such groups already was.
  ([#102](https://github.com/ohstr/nmilat/pull/102))
- Fixes NIP-29 moderation from the relay's own key: NIP-11 `self` now acts
  as admin of every hosted group, so an operator can recover a group whose
  admins are gone. `GroupsService.SetRelayAdmins` adds other operator keys.
  ([#101](https://github.com/ohstr/nmilat/pull/101))
- Fixes NIP-29 `restricted` and `hidden` group flags having no effect: a
  restricted group now refuses posts from non-members, and a hidden group's
  metadata (kinds 39000-39005) is no longer served to non-members.
  ([#100](https://github.com/ohstr/nmilat/pull/100))
- Fixes `Pool` with a Signer waiting 5s before subscribing on relays that never
  send AUTH; it now waits only when challenged, and syncs again after a late AUTH.
  ([#93](https://github.com/ohstr/nmilat/pull/93))
- Fixes `Pool` handing an event on twice in one sync when it arrived both live
  and in a page. ([#93](https://github.com/ohstr/nmilat/pull/93))
- Fixes `Pool` subscribing before NIP-42 AUTH settled and never retrying after
  a `restricted:` or `auth-required:` CLOSED, which left its subscription
  silently dead on relays that require AUTH. ([#91](https://github.com/ohstr/nmilat/pull/91))
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
