# `relay`: a slow subscriber's scan transaction can wedge the entire store

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
`bzzsocial/bzz-feed`), not reproduced synthetically — see "Live incident"
below for the exact commands and output.

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
   exact vendored version this module pins): *"as it grows and it cannot
   do that while a read transaction is open."* Remapping takes
   `db.mmaplock.Lock()` (`db.go:701-702`), which requires every extant
   `RLock()` (taken by *every* transaction, read or write, at `Begin`,
   `db.go:798-812`) to have released first.

5. **Go's `sync.RWMutex` favors the waiting writer.** Once a writer is
   blocked on `mmaplock.Lock()` behind the stale reader from step 3, every
   *new* transaction — including brand-new, unrelated `REQ`s that have
   nothing to do with the original slow subscriber — also blocks, because
   Go blocks new `RLock()` acquisitions once a `Lock()` is pending. One
   slow client turns into a total, relay-wide stall the moment any write
   needs the file to grow.

No `TODO`/`FIXME` referencing this exists in `relay/store.go`,
`subscription.go`, or `handlers.go` as of this writing — this does not
appear to be a previously-flagged, already-triaged issue.

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
landing while some scan's transaction is still open on a slow consumer.

Checked `nmilat` history through `v0.3.1` and current `origin/main`
(`d33a931`), and `ncli` through `v0.5.0` and its current `origin/main`:
no lock/deadlock/bbolt fix addressing this exists yet in either repo.
