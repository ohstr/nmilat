# Community relay readiness — gap analysis and test plan

Status: **P0 #1 fixed and tested** (test #1 below is green; see this
worktree's own PR for the fix). P1 items #2-#4 remain open. Companion doc:
`orgs/ohstr/ncli/.claude/worktrees/community-relay-readiness/docs/private/community-relay-readiness-plan.md`.

## Why this exists

Everything scoped in the original NIP-29 groups plan (`nip29-groups-plan.md`)
and the two follow-up auth fixes (#61, #63, #65) is now shipped and verified
live: create/delete, membership/roles, metadata/invites/pins, the private-
group visibility gate, unconditional NIP-42 challenges, and the
restricted-vs-empty signal. That closes the plan as originally scoped.

This doc is what's left to make a relay genuinely trustworthy and complete
as a **community relay** — the bar `block/buzz` already clears for its own
communities — found by actually exercising every piece end-to-end against
a real relay process rather than trusting unit tests alone. Two real bugs
(the connection-closing retry failure, the challenge/`auth_required`
coupling) were only found this way; assume more are findable the same way,
which is why this doc leads with a test plan, not just a fix list.

## P0 — Critical, fix before calling this ready

### 1. Untagged group queries bypass the entire privacy gate

`groupIDsInFilter` (`relay/groups.go:622-629`) only extracts group ids from
a filter's `d`/`h` tags:
```go
func groupIDsInFilter(filter *nip01.SubscriptionFilter) []string {
    ids = append(ids, filter.Tags["d"]...)
    ids = append(ids, filter.Tags["h"]...)
    return ids
}
```
A REQ with no `d`/`h` tag at all — e.g. `{"kinds":[39000]}` — makes this
return empty, so `deniedPrivateGroupFilter` has nothing to check and the
query runs unrestricted against the whole store.

**Confirmed live, fully anonymous:** a targeted query for a private
group's own `d` tag is correctly denied (empty). The same relay, queried
with a bare `{"kinds":[39000]}` (no tag filter), returned **every group on
the relay**, including the private one — full metadata, `private`/`closed`
tags and all.

This is not a contrived edge case: it's exactly what `ncli groups list`
does by design (an intentionally untagged query, for legitimate public-
group discovery). **Right now, `ncli groups list` run anonymously against
any relay leaks the existence and metadata of every private group on it.**

**Why the obvious fix doesn't work:** denying every untagged group-kind
query outright would break the legitimate discovery use case (`groups
list` needs an untagged query to find public groups at all). The fix has
to move from *request*-filtering to *result*-filtering: for every
`kind:39000/39001/39002` (and eventually `39003-39005`) event about to be
returned, check whether its own group is private, and if so, whether the
requester is an authenticated member of that specific group — drop it
from the response if not, regardless of what the request's filter did or
didn't specify. Public groups pass through unfiltered either way.

**Confirmed untested**, not just unfixed: `relay/groups_test.go`'s four
`PrivateGroupVisibilityGate_*` tests (`DeniesNonMember`, `AllowsMember`,
`PublicGroupUnaffected`, `UnknownGroupUnaffected`) all exercise *tagged*
filters. None exercises a bare, untagged `kind:39000`-series query. This
was a genuine blind spot in the suite, not bad luck — see the test plan
below for what closes it.

## P1 — Real gaps, not urgent

### 2. Group deletion's cleanup scope is undefined and untested

`handleDeleteGroup` (`relay/groups.go:115-140`) removes the group's own
registry entry (`g.Delete(groupID)`) after an admin check, but it's
unverified whether historical content events tagged to that group (chat
messages, artifacts, anything carrying that group's `h` tag) get cleaned
up too, or sit orphaned in the main event store forever — potentially
even resurfacing if a new group is later created reusing the same id.
Pick one behavior deliberately and lock it in with a test; right now
neither is asserted anywhere.

### 3. Group-creation rate limiting is unconfirmed for this specific path

A generic `ErrRateLimited` mechanism exists (`relay/packet.go:581`), but
no test confirms it actually covers `kind:9007` specifically. Creation is
deliberately open to anyone with no membership/auth gate (a correct
design decision, see the original plan) — which makes it the one write
path most exposed to spam if the generic limiter doesn't actually reach
it. Confirm it does, with a test, before calling self-service creation
production-ready.

### 4. No agent-identity delegation layer

`block/buzz` layers NIP-OA (owner attestation) → NIP-AA (agent inherits
owner's membership) → NIP-FI (federated identity) → NIP-IA (archival) on
top of the same NIP-42/43/29 base this relay has. nmilat has none of
these. Orthogonal to group-hosting correctness itself, but relevant if
this relay is meant to host a community *of agents* specifically (an
agent spawned by an already-enrolled human currently needs its own
separate NIP-43 enrollment, with no inherited-access path). Longer-term
parity item, not a blocker for hosting a community today.

## What's confirmed solid, not a gap

- **Role/moderation enforcement is real and already well-tested.**
  `CanPerform(groupID, pubkey, kind)` gates every admin action, and
  `relay/groups_test.go` has a dedicated `_NotAdmin` test for every one of
  them: `PutUser`, `RemoveUser`, `EditMetadata`, `DeleteEvent`,
  `CreateInvite`, `UpdatePinList`, `DeleteGroup`. A non-admin member
  cannot forge a moderation action. Nothing to do here.
- **The NIP-42/auth_required coupling (PR #65) and the connection-closing
  retry bug (PR #61/#63) are fixed and verified live**, including their
  own dedicated regression tests (`relay/packet_test.go`,
  `relay/client/private_group_integration_test.go`).

## Integration test plan

Tests marked **(new)** don't exist anywhere yet. Tests marked
**(extend)** build on an existing suite. Tests marked **(exists)** are
listed for completeness, to show what's already locked in.

### nmilat — `relay/` and `relay/client/`

1. **(done)** Untagged broad query (`kind:39000/39001/39002`, no `d`/`h`
   tag) against a relay with one public and one private group: anonymous
   caller gets only the public group's events; an authenticated member of
   the private group gets both; an authenticated non-member still gets
   only the public one.
   `TestPrivateGroup_UntaggedQueryHidesPrivateGroupFromNonMembers`
   (`relay/client/private_group_integration_test.go`) — confirmed failing
   against pre-fix `main` (leaked the private group to both the anonymous
   and non-member cases), fixed via `deniedPrivateGroupEvent`/
   `deniedPrivateGroupPotentialEvent` (`relay/groups.go`, wired into
   `relay/handlers.go`'s `StandardRequestHandler.Handle`), confirmed green
   including under `-race -count=20`. Closing this also required a
   companion fix in `relay/client.ReadEventsFromRelayWithAuth` (see
   CHANGELOG): an untagged query has no restricted-CLOSED signal to retry
   on, so a fresh connection's first REQ could race its own NIP-42
   handshake and silently under-report a member's own private-group
   content; `subscribeOnce` now also reports whether it ended via *any*
   CLOSED, and the caller retries once more on a race (EOSE reached while
   the handshake was still unresolved) the same way it already retried
   once on an explicit restricted CLOSED.
2. **(new, P1)** `kind:9007` specifically hits the rate limiter after N
   creations from one pubkey in a window (whatever the generic limiter's
   actual unit is) — confirms finding #3 isn't a blind spot in practice.
3. **(new, P1)** Delete a group, then query for content events previously
   tagged to it: assert whichever cleanup behavior is chosen for finding
   #2 (orphaned-but-queryable, or cascade-deleted) — currently neither is
   asserted.
4. **(new)** A full lifecycle integration test in
   `relay/client/private_group_integration_test.go` (extending its real-
   relay pattern, not mocks): create → edit to public+open → invite →
   second identity joins via the invite code → first identity adds a
   third identity as admin via `members add`-equivalent → pin an event →
   delete an event → delete the group — asserting visibility/state after
   every step, against one real relay instance. This is what this entire
   session did by hand, kubectl-exec-by-kubectl-exec; it should never
   again require a human (or an agent) to re-derive it manually.
5. **(exists)** Challenge sent unconditionally regardless of
   `auth_required`/`membership_required` (PR #65, `relay/packet_test.go`).
6. **(exists)** `ReadEventsFromRelayWithAuth` exposes `restricted` instead
   of discarding it (PR #65, `relay/client/reader_auth_test.go`).
7. **(exists)** `processClose` doesn't kill the session on a CLOSE naming
   an already-ended subscription (PR #65, dedicated regression test).
8. **(exists)** Redial-and-reauthenticate if the connection dies mid-wait
   (PR #63, `relay/client/reader_auth_test.go`).
9. **(exists)** Role rejection per admin-action kind (`relay/groups_test.go`,
   the `_NotAdmin` suite listed above).

### ncli — once the P0 fix above ships

10. **(new)** `ncli groups list`, anonymous, against the same
    one-public-one-private fixture as nmilat test #1: confirms the client
    sees what the (now-fixed) relay actually sends, as a second layer of
    confidence independent of the server-side test.
11. **(new)** Full command-surface lifecycle test, the ncli-side mirror of
    nmilat test #4: spin up `ncli relay serve` (ncli's own embedded relay,
    same binary this whole session built and redeployed by hand) as a
    subprocess or container, then drive every `ncli groups` subcommand
    against it in sequence from the CLI itself (not nmilat's library
    directly), asserting `--json` output at each step. Mirrors
    `integration/huddle/`'s existing pattern (a real e2e stack, not mocks)
    — there's no equivalent for groups today.
12. **(new)** Every `ncli groups` write command succeeds against a relay
    with `membership_required: true` *and* `auth_required: false` (the
    exact combination PR #65 made viable) — locks in the specific
    guarantee that fix restored, so a future change can't silently
    reintroduce the all-or-nothing coupling.
13. **(blocked on the ncli-side plan)** `groups show`/`list --identity`
    successfully reading a private group end to end — tracked in the
    companion ncli doc, since it depends on that repo's own still-open
    fix (`--identity` currently ignored by both commands).
