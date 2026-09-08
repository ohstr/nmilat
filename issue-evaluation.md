# Evaluation: "Occasional multi-second silent stall delivering a new event to an already-open REQ subscription"

Source: `issues.md` (community report, `nmilat` v0.2.8).
Method: every code claim in the report was checked line-by-line against `relay/subscription.go`, `relay/config.go`, and `relay/store.go` at the cited version (repo `HEAD` is tagged `v0.2.8`), then traced further downstream into `relay/handlers.go`, `relay/session.go`, and `relay/packet.go`, which the report itself doesn't cite.

**Update, after building the regression tests below**: the original verdict text right below this
("no data is lost... nothing is mis-designed to the point of corruption") is no longer accurate as
a blanket statement. Building a faithful, session-level reproduction of the report's own scenario
(see "Session-level regression test" further down) surfaced a second, independent, more severe bug
— `EventStore.FindEventBytes` could serve actually-corrupted event JSON to a client under
sustained backlog, not just deliver it late. That bug is now fixed (see below). The report's own
empirical claim ("nothing was ever actually lost") still held in *their* environment/scale, and the
latency issue below is still real and still the primary subject of this document — this update
doesn't retract the rest of the evaluation, it corrects one oversold sentence in light of what
digging further up turned.

## Verdict: true positive, real architectural issue, not a phantom report

No data is lost and nothing is mis-designed to the point of corruption *by the mechanism the report
itself describes* (see update above for a corruption bug found by digging further), but the report
accurately
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

## Self-critique (of this evaluation, its fix plan, and the regression test)

Written after re-examining my own conclusions with a skeptical eye. Several things above are
weaker than they were first presented.

**The regression test (`TestSubscriptionBackpressureDelaysButNeverLosesEvents`) does not actually
reproduce the report's own empirical scale.** It requires filling the per-subscription outgoing
channel to its full 55-slot capacity before the poll loop's send blocks. The report's own captured
instance was a burst of **9** concurrent matching events — nowhere near 55. At that volume,
`handleEvents`' send into `sub.outgoing` would never block on its own; the channel has plenty of
spare capacity. So the test's specific trigger (one subscription single-handedly backlogged past
55 unread events) is real and now proven to exist in the code, but it is very unlikely to be *the*
trigger behind the report's numbers. The mechanism I described as most likely in the body of this
document — a slow/blocked `conn.WriteJSON` (no deadline by default) backing up the **shared,
per-connection** `s.incoming` (512 slots, shared across every subscription and control message on
that connection) — needs far fewer matching events on any single filter to manifest, because it
only takes *one* stuck write, anywhere on that connection, to stall the shared consumer goroutine
that every subscription funnels through. That mechanism lives in `session.go`/`handlers.go` and
requires a websocket-level test (two real connections, a client that stops reading) to reproduce
convincingly — I did not write that test. What's committed today is evidence that *a* variant of
the underlying bug class (unbounded blocking send, no timeout) is real and reachable, not evidence
that it's reachable at the report's actual observed burst size.

**The regression test only guards "no loss/no duplication," not "bounded latency."** The report's
actual complaint is latency (a stall), not correctness (nothing is reported lost). My test's only
hard assertions are "the retry subscription sees the event promptly" and "the stalled subscription
eventually delivers everything exactly once" — it has no assertion that would fail if a future
change made the stall *worse* (say, minutes instead of seconds), as long as delivery is still
eventually lossless. A test that actually pins down "the stall must not exceed N poll intervals
once P0/P1 land" would be more valuable, but I don't have a bound to assert yet since no fix has
landed — the honest framing is that this is a characterization test for the current behavior's
integrity, not a regression guard for the reported symptom itself.

**The "fresh retry" subscription in the test isn't a fully matched control.** It's opened *after*
56 matching events already exist in the store, so it observes the fresh event via its initial,
bounded (`fetchUntilEmpty=false`) fetch — a different internal code path than the one the stalled
subscription is stuck in post-EOSE (`fetchUntilEmpty=true`, the live-poll path). It's a fair
black-box proxy for what the report itself measured (a client-side retry), but not an
apples-to-apples internal comparison.

**P0's "give `DataWriteTimeout` a sane non-zero default" doesn't propose a number, because I don't
have one.** Too short, and a legitimately slow-but-not-broken client gets disconnected more often
(trading a silent stall for a spurious close) — a real regression for anyone relying on today's
"wait forever" tolerance, not just a strict improvement. Too long, and it doesn't meaningfully
bound the worst case the report is complaining about. This needs production latency data (e.g. via
the P0 instrumentation, deployed first) to pick a real value, not a guess baked into this document.

**P1's "give each subscription its own write path" is looser than it can actually be.**
`gorilla/websocket` does not support concurrent writes to one `*websocket.Conn` without external
synchronization, so a connection's outgoing traffic cannot be fully de-serialized — there will
always be exactly one writer goroutine per connection. What's actually achievable is *fairer
scheduling* across subscriptions sharing that one writer (e.g. round-robin draining, or a
per-subscription cap on how many consecutive messages one subscription can push before yielding),
not removing the shared bottleneck outright. The write-up as currently phrased could be read as
promising more than that.

**P1's "decouple the poll loop from the drain" needs a bounded design, not just "move it off the
poll goroutine."** If the scan side is fully decoupled from a slow drain via an unbounded
intermediate structure, the failure mode changes from "one subscription's poll loop blocks" (safe,
self-limiting, bounded memory) to "events accumulate somewhere unbounded while a slow consumer
never catches up" (an OOM risk instead of a stall). Any real implementation needs its own
bound-plus-drop/log policy, which is a real design task, not a one-line change.

**P2's write-pipeline critique ("`WorkerCount > 1` can only add latency, never help") is
one-sided.** A multi-worker design *can* legitimately help throughput even with bbolt's
single-writer constraint, by overlapping each worker's (cheap, CPU-only) batch accumulation with
another worker's (expensive, I/O-bound) `db.Update`/fsync — i.e. pipelining accumulation against
commit latency, rather than parallelizing commits themselves (which is impossible regardless). I
already hedged this in the P2 write-up ("unclear... near-zero or negative," suggesting a benchmark
first) rather than asserting fragmentation is strictly bad, and that hedge should stay — a rewrite
here isn't justified without measuring first.

**The "OK gates on commit, so the write pipeline is off the critical path" claim is solid but not
airtight.** It correctly rules the write pipeline out as an explanation for the specific
OK-to-visible gap the report measured. It does not rule out the separate, already-noted mmap-growth
lock possibility (a write transaction growing the on-disk file can briefly block *new* transaction
begins, read or write, relay-wide) as a contributor to occasional short stalls — I flagged this as
low-confidence in the body and that confidence level is the right one, not higher.

**On the `ncli` side-check:** verifying `storeLimiter` is per-connection and that its rejection
path is clean was straightforward and I stand by that verdict (not an `nmilat` bug). One thing I
missed in the original pass and only found while re-examining this: the `ncli` report's own
workaround — raising `MaxConcurrentStoreTasks` from 2048 to 16384 — doesn't fix the underlying
bottleneck, it moves it. `executeStoreTask` (`session.go:182`) only guards a per-session semaphore;
past that, it spawns a goroutine that calls the *store-wide* `EventStore.Execute`
(`store.go:962`), whose own queue (`TaskQueueSize`, default 8192, shared across every connection
on the process, unaffected by `MaxConcurrentStoreTasks`) can itself fill under enough concurrent
submitters. When it does, `Execute`'s `s.taskQueue <- task` send blocks — bounded only by that
task's `ctx` (traced back through `processEvent`/`ProcessPacket` to the session's own long-lived
context, which has no deadline by default) — with no rejection, no log, no timeout. This doesn't
stall the connection's read loop (the blocking happens inside the per-task goroutine
`executeStoreTask` spawns, not inline), but it does mean that specific event's `OK`/rejection can
now go silent for an unbounded time instead of failing fast. In other words: raising the session
ceiling without also raising (or understanding its relationship to) the store-wide queue size
trades a clean, fast, observable `ErrRateLimited` for a shot at the same unbounded-silent-wait
failure class documented for the *subscription* side elsewhere in this document — worth flagging
to whoever applied that workaround, and a concrete reason to be cautious about the `ncli` report's
own recommendation #5 ("make `storeLimiter` degrade gracefully... a bounded queue with
backpressure instead of rejecting"): a version of "queue instead of reject" already exists one
layer down, and it already exhibits exactly the failure mode #5 should be careful not to
reintroduce.

## Regression tests

Three tests, in order of how closely each matches the report's own scale and methodology:

- `TestSubscriptionBackpressureDelaysButNeverLosesEvents` (`relay/subscription_test.go`) — the
  narrowest reproduction: backlogs a single subscription's own 55-slot outgoing channel directly.
  Requires far more events than the report's own observed burst (55+ vs. their 9), so it proves the
  no-timeout-blocking-send bug class exists in the code but not that it's reachable at the report's
  actual scale. Kept as the simplest, fastest, most isolated demonstration of that specific
  mechanism.
- `TestSessionSlowReaderStallsEveryOtherSubscriptionOnThatConnection` (`relay/session_backpressure_test.go`)
  — the faithful one: a real two-connection (three, counting the "retry" control) websocket-level
  reproduction. A large backlog on *one* subscription jams a connection's shared outgoing pipe
  (`Session.incoming`), which stalls delivery to a second, unrelated, low-volume subscription
  sharing that connection — needing only 3 fresh events on the filter actually under test, much
  closer to the report's own 9. Shrinks both ends' OS-level TCP buffers (via a wrapped
  `net.Listener` and the dialed client's own `net.TCPConn`) to make "the peer stops reading"
  reproduce genuine TCP backpressure within ~150 small messages instead of depending on this
  environment's own default buffer sizes, which turned out to be large and inconsistent (see that
  file's doc comment for the calibration notes).
- `TestFindEventBytesSurvivesLaterWrites` (`relay/store_findeventbytes_test.go`) — a best-effort,
  not-fully-reliable standalone check for the corruption bug below (see that bug's own section for
  why it doesn't reliably reproduce in isolation). Kept as cheap defensive coverage of the
  invariant, not as the primary evidence — that's the session-level test above, which reliably
  reproduced the actual corruption 3/3 times before the fix landed.

## Second, independent bug found while building the session-level test: data corruption, not just latency

Building `TestSessionSlowReaderStallsEveryOtherSubscriptionOnThatConnection` surfaced a real,
reproducible (3/3 runs, including under `-race`, which stayed silent throughout) failure distinct
from the latency issue this whole document is otherwise about:

```
sendPacket failed error="json: error calling MarshalJSON for type *wire.EventSubscriptionResponse:
invalid character '\x00' looking for beginning of value" packet_type=*wire.EventSubscriptionResponse
```

**Root cause**: `EventStore.FindEventBytes` (`relay/store.go`) returned bbolt's `Get()` result
directly to its caller, after the read transaction that produced it had already closed:

```go
// before
var eventBytes []byte
_ = s.db.View(func(tx *bolt.Tx) error {
    eventBytes = tx.Bucket(indexEvents).Get(itob(evsid))
    return nil
})
return eventBytes, nil
```

Per bbolt's own documented contract, a `[]byte` from `Get()` is a direct reference into the
mmap'd database file and is "only valid for the life of the transaction... Do not use it outside
of the transaction." `FindEventBytes`'s only caller (`relay/handlers.go`'s per-subscription
consumer) fetches these bytes at *delivery* time and hands them to `s.reply()`, which queues them
into `Session.incoming` for `handleOutgoingMessages` to actually marshal and write later — under
the exact kind of held-for-a-while backlog central to the report this whole document evaluates,
that gap can be substantial. Every other `Get()` call site in this package
(`store_membership.go`) was already safe, because each `json.Unmarshal`s its result *inside* the
transaction closure before returning; `FindEventBytes` was the one exception, kept as a raw-bytes
fast path specifically to avoid a marshal/unmarshal round trip.

**What I could and couldn't pin down**: the observed corruption is specific and consistent (NUL
bytes, not arbitrary garbage), and reproduced reliably through the full session/websocket stack —
but I was not able to reproduce it in a minimal, single-goroutine, standalone bbolt test, even
after forcing thousands of subsequent writes across dozens of separate transactions (well past any
plausible mmap-growth or freelist-reuse threshold) and a version with a concurrent writer/reader
goroutine pair. My best-supported guess is that it requires genuine concurrency — most likely
bbolt's mmap being grown (unmapped and remapped) by a concurrent writer while some other goroutine
still holds a stale pointer into the old mapping, which would also explain why `-race` never
flagged it (an mmap remap is a memory hazard below Go's own memory-model visibility, not an
ordinary data race on a Go-level variable) — but that's inference, not a confirmed mechanism.

This doesn't weaken the case for the fix: copying the bytes out *inside* the transaction closure is
correct and sufficient regardless of which specific bbolt-internal behavior ends up triggering
staleness in practice, because it eliminates the entire class of "reference outlives its
transaction" hazard categorically, not just the specific trigger observed here.

**Fix applied** (`relay/store.go`):

```go
_ = s.db.View(func(tx *bolt.Tx) error {
    raw := tx.Bucket(indexEvents).Get(itob(evsid))
    if raw != nil {
        eventBytes = append([]byte(nil), raw...)
    }
    return nil
})
```

Verified: the session-level test now passes cleanly (3/3 under `-race`), and the full `relay`
package suite still passes.

**Severity note**: this is more severe than the latency issue the rest of this document is about —
a client could receive a payload it can't even parse (or, in a worse case not observed here but not
ruled out, one that parses but decodes to the *wrong* event) instead of just receiving a correct
one late. It's also *only* reachable under conditions adjacent to the reported stall (a large
backlog held for a while before delivery), which is presumably why the community report itself
never observed it — their own scenario was small bursts (9 events), likely well under whatever
threshold makes the underlying mmap/page hazard actually manifest.
