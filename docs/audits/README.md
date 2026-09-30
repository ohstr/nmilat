# nmilat security audits

nmilat had no audit tree until 2026-09-30, which is the reason this file exists rather than
a reason to write it at length. Keep it short. It defines four things: what this repo is
answerable for, how severity is assigned, what counts as evidence, and which surfaces are
security-relevant enough to be worth a round.

## What this repo is answerable for

nmilat is the **wire truth**. It owns the bytes, not the policy. Two other repos —
`lokihub` (the hub / server side) and `cashctl` (the holder / client side) — encode and
decode through it and agree with each other only to the extent that nmilat's types round-trip
faithfully.

That has a specific consequence for how bugs here behave, and it is the whole argument for
the tree: **a defect in nmilat does not look like a defect in nmilat.** It surfaces two
repos away, as a hub that under-charges, a ledger that loses a field, a client that trusts a
value nobody signed. Four known cross-repo defects had their root cause here:

| symptom, where it was seen | root cause here |
|---|---|
| `fees_ppm` silently absent from a hub's advertised terms | a struct field that did not serialize |
| a `"proof":null` four-byte round-trip | `omitempty` absent on a pointer, so absence encoded as a present null |
| a proof id that was deterministic across envelopes | id derived from content with no per-envelope input |
| consolidate delivery failed to decode at the client | an encode/decode pair that disagreed about a shape |

All four are the same species: **a type whose Go value is fine and whose wire bytes are not.**
Round-trip is therefore not a nice-to-have in this repo; it is the repo's job.

Three things nmilat owns that no downstream repo can check for itself:

1. **Authentication material.** `nipcash/transport/proof.go` (`ProofBinding`),
   `nipcash/proof.go`, `nipcash/provenance.go`. If a binding omits a field, every downstream
   authorization decision is made on an under-specified statement and both repos look correct.
2. **The reply key.** `nipcash/transport/response.go` — `DeriveReplyKey` is the *only* thing
   authenticating a hub's answer on the private transport. It was undefined in the spec until
   2026-09-30. A client and a hub deriving it differently is a total availability failure; a
   client deriving it too *loosely* is a total authentication failure.
3. **Limits.** `nipcash/transport/limits.go` — `MaxItems`, `MaxNotAfterWindow` and friends are
   what every downstream budget, throttle and rate limit is sized against. Changing a number
   here re-prices a defence in another repo.

## Severity scale

The severity of a finding is the severity of **what actually happens when it fires**, not how
clever the mechanism is. Four levels, ordered by the standing house rule that money outranks
disclosure and disclosure outranks noise.

| level | meaning |
|---|---|
| **Critical** | money is created, destroyed or moved to a party who should not have it, with no operator action required; or an unauthenticated party can make a correct client accept a lie about money. |
| **High** | money is at risk under a reachable-but-conditional trigger, or an authorization gate can be bypassed, or a value that should be authenticated reaches a downstream ledger unvalidated. |
| **Medium** | information disclosure beyond what the spec concedes (roster, existence, timing oracles), or an availability failure a hostile transport can induce at will. |
| **Low / Informational** | a latent defect with no current trigger; a disclosure the spec already concedes; a divergence between two expressions of one rule that will drift later. |

Two modifiers that apply to this repo specifically:

- **A wire-format defect inherits the severity of the field it drops.** An `omitempty` bug on
  a fee field is a money bug, not a serialization nit. Rate it as the former.
- **A gap in a *test* is rated as the severity of the bug that gap could hide** — not as
  "Low, it's only a test". This is the rule that makes a coverage report comparable to a
  vulnerability report, and it is the only defensible way to rank them together.

## Evidence standard

Non-negotiable, because this repo has repeatedly produced green results that meant nothing.

1. **A severity that is not demonstrated is not a severity.** Mark it **UNVERIFIED** and say
   what would settle it. An UNVERIFIED finding is a legitimate deliverable; an inflated one
   is not.
2. **A claim about a test is proved by naming the exact production mutation the test fails to
   notice.** "This test is weak" is an opinion. "Change `X` at `file:line` to `Y` and this
   test still passes" is checkable, and it is the only accepted form.
3. **Read a passing test's own log output before believing it.** Most false passes in this
   codebase's history were caught this way and almost none by re-reading the code. Ask what
   the run actually exercised.
4. **`-count=1` for anything offered as evidence.** Go caches on the test package's own
   sources, so changing the code under test is not always enough to invalidate a cached pass.
5. **Before claiming a leak, answer: which key encrypts this, and who holds it?** A control
   proving two code paths *differ* is not a control for the threat model. One prior round
   shipped a "confirmed" leak that did not exist because it skipped this question.
6. **Prefer a fake-hostile-peer test to a live one.** nmilat is a library; almost every
   interesting attacker here is reachable from a unit test. `newTestHub` in
   `nipcash/client/batch_e2e_test.go` already lies on demand (`chunkSize`, `dropChunk`) —
   extend it rather than writing a harness.

Conventions: one directory per round, `<topic>-<date>/`, with a `README.md` stating scope and
attacker model. Test files written by an audit are prefixed `audit<Round>_<role>_` and left in
place — a test file carries its own reasoning and has proved more durable than a report.

## First inventory of security-relevant surfaces

Ranked by blast radius, which here means *how far a wrong answer travels before anything can
check it*. `~` marks a surface with no dedicated adversarial test as of 2026-09-30.

### Tier 1 — a wrong answer is accepted as money

| surface | files | why it is tier 1 |
|---|---|---|
| reply-key derivation | `nipcash/transport/response.go` | sole authenticator of a hub's answer; spec-undefined until this session |
| proof binding | `nipcash/transport/proof.go`, `nipcash/proof.go` | any omitted field is an authorization statement nobody made. Known: `item.ID` is absent from the binding (mitigated, not fixed, by a duplicate-request rule) |
| mint provenance | `nipcash/provenance.go` | recovers the *minter* identity a client checks a hub announcement against; forged or absent provenance is a hub-substitution attack |
| token encode/decode | `nipcash/token.go`, `nipcash/cash_string.go` | carries amount, identity mode and embedded secret across repos; embedded `identity_required` is known to go **stale** and a downstream repo has trusted it |
| chunk reassembly | `nipcash/client/batch_send.go` ~ | hub-supplied `total` is load-bearing; a lying or truncating transport must not corrupt state or read as complete |
| **NIP-44 v2 itself** | `nip44/encryption.go` | not "supporting crypto": it is the ONLY authentication on a private-transport reply, since replies are signed by a throwaway ephemeral key on purpose. ChaCha20 is an XOR stream, so the HMAC is all that stops a keyless relay making a same-length edit to a plaintext it forwards. Note also that the hub seals with `go-nostr/nip44` and the client opens with this one — two implementations, one wire |

### Tier 2 — a wrong answer is a bypass or a disclosure

| surface | files | note |
|---|---|---|
| envelope validation | `nipcash/transport/envelope.go`, `validate.go` | duplicate items, nonce handling, `not_after` window |
| announcement discovery | `nipcash/transport/announcement.go` | forged kind-11190, wrong inbox, `NormalizeNodeIdentity` |
| identity normalization | `nipcash/identity.go`, `nipcash/transport/identity.go` | two values that should not compare equal, comparing equal |
| limits | `nipcash/transport/limits.go` | every downstream budget is sized against these constants |
| claim matching | `nipcash/claim.go` | `MatchClaimAuto` decides whether a row is *yours*; a known `connection_key` non-match caused a downstream repo to delete live money |
| partial results | `nipcash/client/batch_outcome.go`, `partial_progress.go` | a `*Many` partial must never report as total |
| client construction | `nipcash/client/client.go` | `Connect` accepts a pairing URI *or* a cash token and succeeds on both, yielding a half-capable client that fails at call time |

### Tier 3 — supporting crypto and transport

`nip04` (sealing), `nip46` (remote signing), `nip47` (the request layer the private
transport rides on), `nip59` (gift wrap), `relay` (a truncating relay is indistinguishable
from a silent hub — filter-limit truncation is a known open bug), `nip19` (bech32 decode).

### Known state of test coverage, 2026-09-30

841 `*_test.go` files; **one** test that names security as its subject
(`nipcash/transport/announcement_test.go`) plus the `auditA_`/`auditB_`/`auditC_` files prior
rounds left behind. There is no negative-path convention. Treat "nmilat is heavily tested" as
a claim about volume, not about adversaries. Three measurements, all from 2026-09-30, for
calibration:

- **Deleting the HMAC check from `nip44.Decrypt` left all 841 test files green.** So did
  changing the `nip44-v2` salt, dropping HKDF-Extract, and swapping `chacha_key` with
  `hmac_key`. The package's conformance guarantee, `nip44/encryption_test.go:72
  TestVectors`, is an **empty function body** whose comment says official vectors would go
  there. Closed for the four mutations above by `nip44/auditC_qa_kat_test.go`; the official
  `nostr-protocol` vectors are still not present and should be.
- **Deleting mint-provenance verification from its only production caller
  (`nipcash/client/client.go:88`) left the whole `nipcash` tree green**, because every test
  in `nipcash/client` builds `&Client{}` with a nil token and hands `NewBatchSession` the
  fake hub's identity directly — the value production has to derive. Closed by
  `nipcash/client/auditC_qa_provenance_chain_test.go`.
- **Fuzzing is pointed the wrong way for a hostile-server model.** `FuzzDecode`
  (`nipcash/transport/envelope_test.go:300`) fuzzes the request envelope, which a hub
  receives from a client. `DecodeResponse` — the decoder a client points at bytes from a
  hostile hub relayed by a hostile relay — has no fuzz target.

The recurring shape, and the thing to check first in any new test here: **a symmetric
round-trip through one implementation is a tautology.** Both halves move together under
every mutation that matters. Re-express the expected value from the primitive the spec
names, or freeze a constant a human checked once.
