# Evaluation: "Occasional multi-second silent stall delivering a new event to an already-open REQ subscription"

Source: `issues.md` (community report, `nmilat` v0.2.8).
Method: every code claim in the report was checked line-by-line against `relay/subscription.go`, `relay/config.go`, and `relay/store.go` at the cited version (repo `HEAD` is tagged `v0.2.8`), then traced further downstream into `relay/handlers.go`, `relay/session.go`, and `relay/packet.go`, which the report itself doesn't cite.

## Verdict: true positive, real architectural issue, not a phantom report

No data is lost and nothing is mis-designed to the point of corruption, but the report accurately
describes a genuine, currently-unbounded and currently-invisible latency path. It's low severity
(self-heals, rare, no data loss) but worth fixing — the failure mode ("an already-open
subscription doesn't see a new matching event for up to 30s, silently") is exactly the kind of
thing that erodes trust in a relay even though the underlying data is fine.

## Fact-check of the report's code claims

Everything the report quotes or paraphrases from `nmilat` v0.2.8 checks out exactly:

| Claim | Verified |
|---|---|
| `Subscription.Start`'s poll loop, 50ms ticker, no broadcast/wakeup path | ✅ `relay/subscription.go:65-83`, byte-for-byte as quoted |
| `eventBufferCapacity = 55` | ✅ `relay/subscription.go:14` |
| `defaultEventStoreConfig`: `WorkerCount=NumCPU()`, `TaskQueueSize=8192`, `BatchSize=500`, `BatchInterval=10ms` | ✅ `relay/config.go:291-307` |
| `storeCursor.SaveLastKey`/`Collect` watermark logic, incl. the `evsid`-boundary special case for the `created_at` index | ✅ `relay/store.go:1120-1245`, matches the described intent and doesn't show an obvious loss path either |
| "No `NOTICE`/error accompanies the stall" | ✅ consistent — there is genuinely no code path that would log anything for slow delivery; it's plain channel/goroutine blocking, not a rejection |

The report's authors clearly read the actual source rather than guessing — this is above the
median bar for a community report and the maintainers can trust the code citations without
re-deriving them.

## Where the report's own analysis under- and over-shoots

**Over-shoots (a red herring the report treats as its top suspect):** the report calls "the
batched-write pipeline... the most promising place to add instrumentation." Having traced the
publish path in `relay/packet.go`, this is very likely *not* a contributor to the specific gap
being measured. `OK true` is sent to the publisher only after the insert `Task`'s `Done()` fires,
which happens *after* `ExecuteBatch`'s `db.Update` has committed
(`relay/packet.go:456-465`, `relay/store.go:274-324`). That means by the time the report's own
measurement clock starts ("wall-clock gap between the relay accepting the EVENT (`OK true`) ...
and connection A receiving that event"), the write has already landed — there is no remaining
store-write latency left to explain the gap. Worth instrumenting for its own sake (see the
independent finding below), but it's the wrong place to look for *this* symptom.

**Under-shoots (the report stops one layer too early):** the report's third candidate —
"downstream per-subscription channel backpressure... if a slow consumer fills it would block
that subscription's own scan-goroutine send" — is on the right track but doesn't look at what's
*downstream of* the 55-slot `outgoing` channel. That consumer is
`StandardRequestHandler.Handle`'s per-subscription goroutine (`relay/handlers.go:141-176`), which
for every event does a synchronous `FindEventBytes` + `s.reply()`. `reply()`
(`relay/packet.go:558-569`) pushes into `Session.incoming`, a single channel **shared by every
subscription and every control message on that connection**, buffer size 512
(`relay/config.go:236`, `relay/session.go:172-176`), drained by exactly one goroutine
(`handleOutgoingMessages`, `relay/session.go:412-427`) doing one blocking `conn.WriteJSON` call at
a time (`sendPacket`, `relay/session.go:429-462`). Critically:

```go
// relay/config.go
DataWriteTimeout: 0, // no hard data deadline by default
```
```go
// relay/session.go, sendPacket
if s.config.DataWriteTimeout > 0 {
    _ = s.conn.SetWriteDeadline(...)
} else {
    var zero time.Time
    _ = s.conn.SetWriteDeadline(zero)   // <- unbounded
}
```

With the default config, a single momentarily-slow TCP reader on the client end (a busy client
event loop, a network blip, OS scheduling pressure — anything, not necessarily high published
volume) makes `conn.WriteJSON` block for as long as it takes the peer to catch up, with **no
timeout, no error, no log**. While it's blocked:

1. `handleOutgoingMessages` can't drain `s.incoming` for *any* subscription or control message on
   that connection — not just the one under test.
2. Once `s.incoming` (512) fills, `reply()`'s send blocks too.
3. That backs up `sub.outgoing` (55) for whichever subscription is trying to deliver.
4. `handleEvents`'s blocking channel send (`relay/store.go:1488-1493`) then blocks *inside*
   `Fetch()`, which is called synchronously from `Subscription.Start`'s `select` on `<-ticker.C`
   (`relay/subscription.go:70-78`) — so the poll loop's own next ticks can't fire either, and
   `<-sub.closeCh` can't be selected until `Fetch` returns (only `Stop()`'s `context.CancelFunc`
   can unstick it, via `ctx.Done()` inside `handleEvents`'s select).

This chain reproduces every empirical detail in the report: silent (no rejection path exists),
self-clearing (once the peer catches up, everything queued flushes essentially at once), no data
loss, fast immediate retry (a fresh request has no backlog ahead of it), and a magnitude that can
genuinely reach seconds — bounded only by how long the client (or the OS/network) takes to resume
reading, which under "sustained concurrent load" (the report's own reproduction shape) is exactly
when a client is most likely to be momentarily slow to read its own socket.

The pure 50ms poll floor, by itself, cannot explain multi-second/30s outliers (600+ missed poll
cycles) — the report says as much, correctly.

## Independent finding not in the report

`handleTasks`'s `WorkerCount = runtime.NumCPU()` goroutines each build their **own** independent
batch and each call `s.db.Update()` directly (`relay/store.go:326-397`). `bbolt` only allows one
writer transaction process-wide (`db.rwlock`), so with `WorkerCount > 1` these goroutines don't
parallelize writes — they can only serialize against each other for the same lock. Under bursty
concurrent publish load this fragments what could be one well-coalesced transaction into several
smaller ones, each paying its own `BatchInterval` (10ms) timer *and* queueing time behind the
others, each with its own commit/fsync. This doesn't affect the report's specific
OK-to-visible-on-subscription symptom (OK still gates on commit either way), but it likely
inflates publish (`OK true`) tail latency under burst load, and is a reasonable secondary
finding while anyone is in this code for the stall fix.

## Recommendation

Fix, in this priority order:

### P0 — bound the blocking write, make it observable (small, low-risk)
- Give `DataWriteTimeout` a sane non-zero default (or otherwise cap `conn.WriteJSON`'s deadline)
  so one slow reader can no longer block a connection's outgoing pipeline indefinitely. On
  timeout, treat it like any other write failure (close the session) rather than hanging forever.
- Add a debug-log/metric for: `len(sub.outgoing)`, `len(s.incoming)`, and time spent blocked in
  `reply()`/`sendPacket` past some threshold (e.g. >50ms). This directly answers the report's own
  ask ("this currently produces zero observable signal") and would have let them self-diagnose.

### P1 — stop one slow consumer from starving the whole poll loop
- Don't let `handleEvents`'s send into `sub.outgoing` (`relay/store.go:1488-1493`) be the same
  synchronous call that gates `Subscription.Start`'s next ticker case. Either send with a bounded
  timeout (log+drop/close-subscription on persistent overflow) or move the drain off the poll
  goroutine, so a subscription's own scan/poll cadence is decoupled from how fast its consumer
  happens to be draining right now.
- Consider giving each subscription's delivery its own write path instead of funneling every
  subscription on a connection through one shared `s.incoming`/`handleOutgoingMessages` — at
  minimum, a large burst on one subscription (or slow reads generally) shouldn't visibly delay
  delivery to every *other* subscription open on the same connection.

### P2 — remove the poll floor (larger, more invasive)
- Add an event-driven wakeup: after a successful commit, nudge open subscriptions whose filters
  could match (or just nudge all of them — the poll conservatively over-triggers already) instead
  of relying solely on the 50ms ticker. Keep the ticker as a safety net/fallback rather than
  removing it outright, to avoid making event-driven wakeup a new single point of failure for
  liveness.

### P2 — write-pipeline coalescing (independent finding)
- Either use a single dedicated writer goroutine that batches everything (removing the
  multi-worker lock-fragmentation described above), or hand batches through a shared
  batch-builder so concurrent submissions actually coalesce into fewer, larger `db.Update` calls
  instead of several small ones serializing against the same lock. Worth a benchmark first —
  `WorkerCount`'s actual benefit given bbolt's single-writer constraint is unclear and might be
  near-zero or negative under burst load.

### P3 — docs
- Document `DataWriteTimeout=0`'s footgun explicitly (unbounded write blocking, shared per
  connection across all subscriptions) so downstream deployers can make an informed choice even
  before/instead of a default change.

## What I would *not* do

- Don't chase the batched-write pipeline as the primary fix target for this specific symptom —
  it's very likely not on the critical path for it (see above). Instrument it anyway (P2) since
  it's cheap and has its own independent tail-latency value, but don't expect it to move the
  needle on this report's numbers.
- Don't over-rotate into a full push/broadcast redesign (P2, poll floor) before landing P0/P1 —
  the write-timeout + backpressure-decoupling fixes are cheap, low-risk, and directly address the
  mechanism that best explains the reported magnitude (seconds, not tens of milliseconds); the
  poll-floor redesign is real but addresses a much smaller (~50ms) piece of the observed gap.

## Suggested next step to actually confirm before landing fixes

The report itself flags they haven't isolated a standalone repro or correlated a live occurrence
against a specific event ID. Given the mechanism identified above, the cheapest confirmation
would be: reproduce the report's step 1-4 shape while have one of the N concurrent "publisher"
connections *also* act as a deliberately slow reader on its own open REQ subscription (e.g. don't
read from the websocket for 2-3s under load) and confirm that *other*, unrelated subscriptions on
a *different* connection are unaffected, while other subscriptions on the *same* connection as the
slow reader stall too. That would directly confirm the shared-per-connection-pipe theory over the
poll-floor-only theory, and is a much smaller lift than instrumenting the write pipeline (which
the report suggested, but which this evaluation argues is the less likely culprit).
