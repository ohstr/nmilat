# Delivery stall: root cause and fix

Community report: an already-open `REQ` subscription occasionally doesn't see a newly-published
matching event for many seconds, with no `NOTICE`/error, under concurrent write load. Verified
against `nmilat` v0.2.8. Verdict: real bug, low severity (self-heals, no data loss from this
mechanism), now fixed.

## Root cause

Every subscription **and** every control message (OK/EOSE/etc.) on one websocket connection shares
a single outgoing pipe: `Session.incoming` (512 slots), drained by one goroutine
(`handleOutgoingMessages`) making one blocking `conn.WriteJSON` call at a time. `sendPacket` set no
write deadline by default (`DataWriteTimeout: 0`), so a single slow or stuck reader on that
connection could block that goroutine indefinitely, with no error and no log. That backpressure
cascades: `Session.incoming` fills → `reply()` blocks → the per-subscription 55-slot channel fills →
`handleEvents`'s blocking send inside `Subscription.Start`'s poll loop blocks too, stalling that
subscription's own next ticks.

This reproduces every symptom in the report: silent (no rejection path exists), self-clearing
(queued messages flush once the peer catches up), no data loss, fast retry (a fresh subscription has
no backlog), and unbounded duration (bounded only by how long the peer takes to resume reading).

The report's own top suspect — the batched-write task queue — is **not** the cause: `OK true` is
only sent after the insert task's commit completes, so by the time a publisher sees `OK`, the write
pipeline is already off the critical path for how long the *subscriber* takes to see it.

## Fixes applied

**`relay/config.go`, `relay/session.go`** — the write-chokepoint itself:
- `DataWriteTimeout` now defaults to 30s instead of `0`. Still overridable via
  `WithSessionWriteTimeouts` (including back to `0`). Not a tuned optimum — a deliberately generous
  bound long enough to absorb the report's worst observed stalls (~30s) without punishing a merely
  slow reader.
- `sendPacket` logs a warning when a single write exceeds 250ms, with elapsed time and queue depth —
  previously this produced no observable signal at all.
- Note: full teardown of a *totally* unresponsive peer (one that also never sends PONGs) still
  depends on the separate, pre-existing `PongTimeout` (60s default, unchanged).

**`relay/store.go`** — a second, independent bug found while building the regression test below:
`EventStore.FindEventBytes` returned bbolt's `Get()` result after its own read transaction had
already closed. Per bbolt's documented contract, that byte slice is only valid for the
transaction's lifetime; reproduced 3/3 times as corrupted (NUL-byte) event JSON served to a client
under a held-for-a-while backlog, instead of just late delivery. Fixed by copying the bytes inside
the transaction closure. Exact trigger mechanism unconfirmed (likely bbolt mmap growth racing a
stale reference — inference, not proven), but the fix removes the whole hazard class regardless.

## Regression tests

- `TestSubscriptionBackpressureDelaysButNeverLosesEvents` (`relay/subscription_test.go`) — direct,
  narrow reproduction of the blocking-send mechanism (needs 55+ backlogged events on one
  subscription; the report's own bursts were closer to 9).
- `TestSessionSlowReaderStallsEveryOtherSubscriptionOnThatConnection`
  (`relay/session_backpressure_test.go`) — real two-connection websocket reproduction: a backlog on
  one subscription stalls an unrelated, low-volume subscription sharing the same connection, needing
  only a handful of fresh events — closer to the report's actual scale.
- `TestDataWriteTimeoutClosesAPermanentlyStuckReaderInsteadOfHangingForever`
  (`relay/session_backpressure_test.go`) — confirms a connection whose peer never reads at all now
  gets closed within a bounded time instead of hanging forever.
- `TestFindEventBytesSurvivesLaterWrites` (`relay/store_findeventbytes_test.go`) — best-effort check
  for the corruption bug; doesn't reliably reproduce it standalone (needs the concurrency the
  session-level test provides), kept as cheap defensive coverage.

Full module + `relay` package under `-race` verified passing.

## Remaining work (not done here)

- **Fairness**: one slow subscription can still starve others on the same connection before hitting
  the write timeout. Needs either a bounded send with drop/log on persistent overflow, or
  round-robin scheduling across a connection's shared writer (full parallelism isn't possible —
  `gorilla/websocket` forbids concurrent writes to one connection).
- **Poll floor**: subscriptions are purely 50ms-polled, no event-driven wakeup. Real, but a much
  smaller contributor (~50ms) than the write-chokepoint above (seconds).
- **Write-pipeline coalescing**: `handleTasks`'s `WorkerCount` workers each build independent
  batches against bbolt's single writer lock — may or may not help throughput (pipelines batch
  accumulation against commit latency, but also fragments large batches); needs a benchmark before
  changing.
