# `relay`: a `REQ`'s scan transaction can wedge the entire store

## Summary

`relay.EventStore`'s query path (`storeScan.scan`) runs the *entire*
collection-and-delivery loop for a `REQ` — including the network write to
the subscriber — inside a single, long-lived `bolt.DB.View` read
transaction. If delivery to that one subscriber stalls (a slow or
half-dead connection), the read transaction stays open indefinitely. Bolt
cannot grow/remap its mmap while any read transaction is open, and Go's
`sync.RWMutex` blocks *new* readers once a writer is waiting on that remap
— so one stuck subscriber, combined with one write that needs the file to
grow, freezes every other connection on the relay: new `REQ`s hang with no
response, and new `EVENT` publishes fail. NIP-11 and plain TCP/WS accept
keep working throughout, since they never touch `db.View`, which is what
makes this silent under a simple TCP-socket health probe.

This was root-caused live against a real deployment (downstream project:
`bzzsocial/bzz-feed`) — see "Live incident" below for the exact commands
and output — and has since been **reproduced in-tree**. See
"Reproduction" below for the tests and their output.

The in-tree work also turned up something worse than this summary
originally claimed: the stall does **not** actually require a slow
subscriber. A perfectly healthy, fast client is enough. See "The delivery
loop deadlocks against itself".

## The mechanism, with citations (as of `nmilat` `2b5740b`, tag `v0.3.1`)

1. **A `REQ`'s read transaction spans the whole delivery loop, not just
   the lookup.** `relay/store.go:1426-1428`:

   ```go
   err := ss.store.db.View(func(tx *bolt.Tx) error {
       return runScan(tx)
   })
   ```

   `runScan` (`relay/store.go:1331-1420`) iterates every cursor for the
   filter, and for each batch calls `handleEvents`
   (`relay/store.go:1475-1509`), which does:

   ```go
   select {
   case potEvents <- potEvent:
   case <-ctx.Done():
       ...
   }
   ```

   `potEvents` is the subscription's own outgoing channel, capacity 55
   (`eventBufferCapacity`, `relay/subscription.go:15`). The `db.View`
   closure — and the read transaction it holds — does not return until
   every cursor is exhausted or `ctx` is cancelled. This is true for a
   one-shot historical query exactly as much as for a live subscription:
   `handlers.go:130` builds a `Subscription` for *every* `REQ`, then
   `handlers.go:149` does `go sub.Start(ctx, &wg)`, and `Subscription.Start`
   (`relay/subscription.go:45-56`) calls straight into
   `sub.query.Fetch(ctx, sub.outgoing, wg, false)`, i.e. the same
   `db.View`-wrapped scan.

2. **The channel is drained one event at a time, and each one is a full
   network round-trip.** `relay/handlers.go:153-160`:

   ```go
   case event := <-toSend:
       eventBytes, err := s.store.FindEventBytes(event.Evsid)
       if err == nil {
           s.reply(&wire.EventSubscriptionResponse{...})
       }
       wg.Done()
   ```

   `s.reply` → `sendPacket` (`relay/session.go:436-481`) takes
   `s.writeMu`, sets a write deadline of `DataWriteTimeout` (30s default,
   `relay/config.go:20`), and blocks on `conn.WriteJSON`. This is fully
   serial: the next event isn't even read off `toSend` until the current
   one's `wg.Done()` fires, which only happens after that write returns
   (success *or* timeout).

3. **So a filter matching more than 55 events against a slow subscriber
   can hold the transaction open for a long time.** Worst case: up to
   `DataWriteTimeout` (30s) *per event*, serialized, for however many
   events matched — several minutes is easily reached on a real backlog.
   The cancellation safety net (session write failure → `cancel()` on the
   session's root context, `session.go:405-408`, which is the parent of
   the subscription's own `context.WithCancel` in `subscription.go:46`)
   only fires once `sendPacket` actually returns an error — a merely slow
   (not yet failed) peer, or any gap in that propagation under load,
   leaves the transaction open the whole time.

4. **Bolt cannot remap while a read transaction is open.**
   `go.etcd.io/bbolt@v1.5.0/db.go:759` (comment, verified against the
   exact version this module pins): *"as it grows and it cannot do that
   while a read transaction is open."* The remap is `db.mmap()`, which
   takes `db.mmaplock.Lock()` (`db.go:457-458`). A write reaches it via
   `tx.Commit` → `db.grow` → `db.allocate` → `db.mmap`, guarded by
   `if minsz >= db.datasz` (`db.go:1205-1206`).

   Only *read* transactions hold `mmaplock.RLock()`: `beginTx` takes it at
   `db.go:801` and releases it in `removeTx` (`db.go:877`). A write
   transaction's `beginRWTx` (`db.go:838-870`) takes `rwlock` and
   `metalock` only, and never touches `mmaplock` — so starting a write
   while a read transaction is open is fine; it is the *commit's* remap
   that waits.

5. **Go's `sync.RWMutex` favors the waiting writer.** Once `db.mmap()` is
   blocked on `mmaplock.Lock()` behind the stale reader from step 3, every
   *new read* transaction — including brand-new, unrelated `REQ`s that
   have nothing to do with the original slow subscriber — also blocks,
   because Go stops admitting new `RLock()` acquisitions once a `Lock()`
   is pending. One slow client turns into a total, relay-wide stall the
   moment any write needs the file to grow.

   `TestBoltNewReadTransactionBlocksBehindAGrowingWrite` confirms all
   three of these behaviors directly against the pinned bbolt, with no
   `nmilat` code involved.

### Prior art

An earlier pass did flag part of this. The PR #19 self-critique
(`issue-evaluation.md`, commit `476ef15`) noted "the separate,
already-noted mmap-growth lock possibility (a write transaction growing
the on-disk file can *briefly* block *new* transaction begins, read or
write, relay-wide)" — correctly, but at low confidence, and on the
assumption that the block would be brief.

What is new here is step 3: the scan's read transaction is held for as
long as *delivery* takes, not as long as a commit takes. That upgrades
"briefly blocks" to "blocks until the subscriber drains, or forever" —
which is the difference between a latency blip and the observed
wedge-until-restart. (The prior note's parenthetical is also slightly
off, per step 4: a write transaction's *begin* is not blocked, only a
remapping commit.)

## The delivery loop deadlocks against itself

The framing above — "a *slow* subscriber wedges the store" — understates
this. No slow peer is required.

`handlers.go:154`'s delivery loop calls `s.store.FindEventBytes(event.Evsid)`
for every event it takes off the channel, and `FindEventBytes`
(`store.go:1016`) opens its **own** `db.View`: a brand-new read
transaction, subject to step 5 like any other. So with a growing write
pending, the cycle closes on itself:

```
scan holds read transaction A open, parked on a full 55-event channel
  -> the growing write waits on mmaplock.Lock() behind A
    -> the delivery loop's FindEventBytes blocks starting transaction B
      -> the loop cannot drain the channel
        -> the scan never finishes, so A never closes
          -> the write never proceeds  (back to the top)
```

Consequences:

- **A healthy, fast client is enough.** The trigger is just: any filter
  matching more than `eventBufferCapacity` (55) events, plus one
  concurrent write that grows the file. No slow reader, no half-dead
  connection, no network stall.
- **Nothing times out of it.** `DataWriteTimeout` only bounds
  `conn.WriteJSON` (`session.go:449`), which this never reaches — the
  loop is stuck one call earlier, in `FindEventBytes`. So the
  write-failure `cancel()` path (`session.go:405-408`) never fires, and
  the only ways out are the subscription's own context being cancelled or
  a process restart.

This matches the live incident better than the slow-subscriber reading
does: it explains why *every* `REQ` hung rather than just those on
degraded connections, and why a pod restart was needed.

`TestDeliveryLoopDoesNotDeadlockWhenAWriteGrowsTheStore` reproduces
exactly this, and delivers **0 of 200** events.

## Reproduction

`relay/store_scan_transaction_test.go`. The first three tests assert the
invariant that *should* hold, so they fail against the current scan; that
failure is the reproduction, and they go green once the fix below lands.
The fourth pins bbolt's own semantics and passes today.

```
GOWORK=off go test ./relay/ -run 'TestScanDoesNotHold|TestGrowingWrite|TestDeliveryLoopDoesNot|TestBoltNewRead' -race -count=3
```

Verbatim output (identical across 3 race-enabled runs — this is
deterministic, not timing-dependent):

```
--- FAIL: TestScanDoesNotHoldReadTransactionAcrossDelivery (3.33s)
    scan held 1 bolt read transaction(s) open continuously for 500ms
    while 55 event(s) sat undelivered in the subscription buffer.

--- FAIL: TestGrowingWriteDuringStalledScanDoesNotBlockUnrelatedReaders (14.07s)
    an unrelated read transaction was still blocked 5s after it started,
    because a stalled subscriber's scan is holding a bolt read transaction
    open and a growing write is waiting to re-mmap behind it.
    a file-growing write was still blocked 5s after it started, for the
    same reason -- which is why new EVENT publishes fail while this is
    happening.

--- FAIL: TestDeliveryLoopDoesNotDeadlockWhenAWriteGrowsTheStore (6.92s)
    delivery stopped after 0 of 200 events and made no further progress
    for 3s, with a perfectly healthy consumer.

ok  TestBoltNewReadTransactionBlocksBehindAGrowingWrite
```

Notes on method:

- The instrument for "is a transaction held?" is bolt's own
  `db.Stats().OpenTxN` ("number of currently open read transactions",
  `db.go:1432`). The tests compare the **minimum** over a sampling window,
  not the maximum: a *held* transaction keeps the count above zero for the
  whole window, whereas incidental background reads only lift it
  momentarily. The baseline with no scan running is asserted to be 0
  first, so a held transaction can be attributed to the scan.
- Both write-dependent tests assert afterwards that the database file
  actually grew, so they fail loudly rather than passing vacuously if the
  write ever stops being large enough to force a remap.

## Suggested fix direction

Don't hold the read transaction open across delivery. Collect the
matching event IDs/bytes for a batch inside `db.View`, close the
transaction, *then* hand the batch off to the per-connection delivery
loop. `relay/store.go`'s own `04b4543` (`fix(relay): copy FindEventBytes'
result out of its bbolt transaction`) already established this pattern
for a single lookup; the same principle needs to apply to the whole scan,
not just one call inside it. Bounding `runScan`'s own `ctx` with a
deadline independent of the parent subscription/session context (rather
than relying solely on the session write-failure path to propagate
cancellation) would also shrink the exposure window.

Doing that also resolves the self-deadlock above, since transaction A
stops existing during delivery. Worth folding in while there: the
delivery loop re-reads each event with `FindEventBytes`
(`handlers.go:154`) right after the scan already had it in hand, so
carrying the bytes through on the `PotentialEvent` would remove a whole
second read transaction per event from the hot path regardless.

The three failing tests in `relay/store_scan_transaction_test.go` are the
acceptance criteria — they turn green when the transaction no longer
spans delivery.

## Live incident (downstream: `bzzsocial/bzz-feed`, 2026-09-22)

Confirmed live on `ghcr.io/ohstr/ncli:0.4.9` (pins this module at
`v0.2.9`). Symptom: the feed's last published post was stuck ~11h in the
past; `feedworker` (a subscriber/publisher client) was crash-looping (75
restarts in 12h) on:

```
ERROR feedworker exited with error error="worker \"feed-trending-f2:4h\": ...
publish: sink publish failed after 3 attempt(s): nmilatsink: publish ...:
relayconn: connection closed waiting for OK: failed to get reader:
received close frame: status = StatusNormalClosure"
```

Reproduced the relay-side half of this directly against the live pod:

```
$ ncli ping ws://localhost:5500
connectivity OK relay=localhost:5500          # plain TCP/WS: fine

$ curl -H "Accept: application/nostr+json" http://localhost:5500/
{"name":"bzz-feed", ... "auth_required":false, ...}   # NIP-11 HTTP: fine

$ ncli find --relays ws://localhost:5500 --kinds 1 --limit 1 --timeout 6s
ERR localhost:5500: no response after 6s, skipping    # REQ/EOSE: hangs

$ ncli dump --relays /data/db/notes.db --kinds 1 --limit 1 --out /tmp/x.json --timeout 6s
ERR failed to open db:/data/db/notes.db reason: timeout   # on-disk lock: stuck
```

This is a *recurrence* of an incident this same downstream project first
saw and documented on 2026-09-14, on the same pinned relay version,
before this root cause was traced — see `bzzsocial/bzz-feed`'s
`deploy/helm/bzz-feed/templates/ncli-relay-statefulset.yaml` (its own
"KNOWN GAP" comment) for their independent, symptom-level diagnosis
(process answers TCP/NIP-11 but every `REQ`/`EOSE` hangs and the on-disk
lock times out; a plain pod restart clears it, no data recovery needed).
That project's ingest pipeline pulls continuously from a 56-relay
upstream pool, which is the kind of sustained write volume that needs the
store's mmap to grow/remap often — raising the odds of a growing write
landing while some scan's transaction is still open. (Given the
self-deadlock above, "on a slow consumer" is not even a precondition;
sustained write volume against ordinary `REQ` traffic suffices.)

Checked `nmilat` history through `v0.3.1` and current `origin/main`
(`d33a931`), and `ncli` through `v0.5.0` and its current `origin/main`:
no lock/deadlock/bbolt fix addressing this exists yet in either repo. The
regression tests added alongside this write-up cover the behavior but do
not change it — the scan is still transaction-bound across delivery.
