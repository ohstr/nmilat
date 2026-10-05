# NIP-29 groups — implementation plan (Phases 1–3)

Status: **Phases 1, 2, and 3 all implemented**, in this same worktree
(`worktree-nip29-groups-phase1`, branched off `main` at `888a6ea`), tracked
in ohstr/nmilat#54 and shipped in ohstr/nmilat#56 (#55 was its predecessor,
closed as unmergeable after an upstream commit-message rewrite orphaned its
branch's base commit). `relay/groups.go`,
`relay/groups_cache.go`, and `relay/store_groups.go` now cover every kind
listed below (9000/9001/9002/9005/9007/9008/9009/9010/9021/9022), plus the
REQ/COUNT private-group visibility gate. See each phase's own section for
what actually shipped versus what was originally scoped -- two notable
departures from the letter of the plan: the roster model ended up richer
than "flat admin/member lists" (see Phase 2's note), and `GroupsService`
exposes a `ModerationPolicy` an embedder can override rather than hardcoding
nmilat's own single-role default permanently.

## Why

`nip29/` today is a structural validator only. `nip29/relayreg/relayreg.go`
says so explicitly: it can tell you a 9000-series event is well-formed, and it
auto-declares NIP-29 in NIP-11, but there is no server-side group state behind
it — no record of which groups exist, who is in them, or what roles they
hold. Two things are deliberately left undone because this layer "does not
have" the state for them: verifying a moderation event's signer holds a
permitting role, and verifying relay-authored 39000-39005 events are signed by
the relay's own key. Nothing else in the repo fills that gap (`find . -iname
'*group*' -name '*.go'` outside `nip29/` returns nothing), unlike NIP-43
membership, which has a full `relay/membership_cache.go` +
`relay/store_membership.go` pair.

Meanwhile `block/buzz` (a sibling org's relay, different codebase, not this
one) already has a real, working channel/group model: `buzz-admin
ReconcileChannels` backfills kind:39000/39001/39002 discovery events, and
"channel" is a live concept throughout `buzz-relay` (`connection.rs`,
`subscription.rs`, `router.rs`, `state.rs`). That's the bar nmilat should
match for ncli.

## Decisions locked (do not re-ask the user)

1. **Group creation (`kind:9007`) requires no prior NIP-43 relay
   membership.** Anyone may create a group — matches strict NIP-29 spec
   language (group creation is a normal self-service client action, not an
   operator gate). Do not wire group creation into the `relay/membership.go`
   access check.
2. **A freshly created group defaults to private + closed** (invisible to
   non-members, join requires admin approval) until the creator edits
   `kind:9002` metadata to change it.
3. Green light given to start immediately — this worktree is that start.

## Model to copy

`relay/membership.go` (service + event dispatch), `relay/membership_cache.go`
(in-memory state), `relay/store_membership.go` (bbolt persistence), plus
`membership.go`'s `publishSelfSigned` helper for relay-signed mirror events.
NIP-29 groups need the same trio, scoped per-group instead of relay-wide.

## Phase 1 scope (this worktree)

Create/delete — the actual missing piece:

- `relay/groups.go` — `GroupsService.HandleEvent`, wired into the same
  insert hook `MembershipService` uses (see how `relay/membership.go` hooks
  into `relay/packet.go` today — follow that wiring exactly, don't invent a
  second hook mechanism).
- `relay/store_groups.go` — bbolt persistence, mirroring
  `relay/store_membership.go`'s shape (one bucket per group, keyed by group
  id / `d` tag).
- `relay/groups_cache.go` — in-memory `GroupsCache`, mirroring
  `relay/membership_cache.go`'s `IsMember`-style read path.
- `kind:9007` → create the group. Creator becomes sole admin. No NIP-43 gate
  (decision 1). Relay self-signs+stores `kind:39000` (metadata, defaulted
  private+closed per decision 2), `kind:39001` (admins — just the creator),
  `kind:39002` (members — just the creator) via the existing
  `publishSelfSigned` pattern.
- `kind:9008` → admin-gated teardown. Only an existing admin (per the
  group's own 39001 roster, not relay-wide role) may delete.
- Tests mirroring the existing style: `relay/groups_test.go`,
  `relay/store_groups_test.go`, `relay/groups_cache_test.go` — follow
  `relay/membership_test.go` / `relay/store_membership_test.go` /
  `relay/membership_cache_test.go` for fixture and assertion shape.
- Wire `relay.RegisterNIP(29)` association (currently only
  `nip29/relayreg` does this for the structural-validation side) so a
  relay-embedding binary that wants real group hosting pulls in
  `relay/groups.go` too — decide at implementation time whether that's a
  second blank-importable package or folds into the existing `relayreg`.

### Visibility gating — added 2026-10-05, do not skip

Decision 2 (private+closed default) is a no-op without this. "Private"
must mean something at REQ time, not just at creation time, or every group
is public in practice the moment it's created.

- `relay/packet.go` already has the pattern to copy: it rejects restricted
  REQ/EVENT with `"restricted: valid NIP-42 authentication required"` and
  `"restricted: valid NIP-43 membership required"` (see the existing calls
  around `relay/packet.go:54,58,69,313,475,480`). A private group's own
  `kind:39000`/`39001`/`39002` events — and, once Phase 2 ships, any
  group-addressed content — need the equivalent: a REQ naming a private
  group's `d`/`h` tag MUST come from a session that passed NIP-42 AUTH
  *and* whose authenticated pubkey is in that group's own 39002 roster
  (checked via `GroupsCache`, not the relay-wide `MembershipService`).
  Public groups skip this; closed-vs-open only gates *join*, not *read*.
- This means `GroupsCache` needs a membership-check method shaped like
  `MembershipCache.IsMember`, but keyed by (group id, pubkey) instead of
  just pubkey, and `relay/packet.go`'s REQ path needs a new branch calling
  it for group-tagged filters.
- Coordinate with `ncli`: its generic connection path (used by
  `find`/`publish`/`stream`/`sync`/`inspect`) does not perform a NIP-42
  handshake at all today — only the huddle path does
  (`huddleclient.go:238`). Until ncli's side of this ships too (tracked in
  a matching plan in the `ncli` repo, see
  `docs/private/nip42-generic-auth-plan.md` there), a legitimate member
  running `ncli find` against their own private group will get a silent
  empty result, indistinguishable from "group doesn't exist" — do not
  mistake that for a relay-side bug while testing.

## Phase 2 — implemented

Membership/roles: `kind:9000`/`9001` (put/remove user) and `kind:9021`/`9022`
(group-scoped join/leave — distinct from NIP-43's own join/leave kinds),
enforced through `nip29.ModerationPolicy` (already written in `nip29/`,
wired live for the first time here — closing exactly the "signer holds a
permitting role" gap called out in `relayreg.go`). Updates `kind:39001` /
`39002`.

Shipped shape: `GroupRecord.Members` is `[]GroupMember{Pubkey, Roles}`
rather than the flat `Admins []string` / `Members []string` pair Phase 1
started with — a role-less entry is an ordinary member, holding at least
one role is what this package calls an admin (`GroupRecord.IsAdmin`).
`GroupsService.CanPerform(id, pubkey, kind)` asks `ModerationPolicy`
whether pubkey's own roles permit `kind`; `defaultGroupModerationPolicy`
(in `relay/groups_cache.go`) is nmilat's own single-role answer to the
NIP-29 text that leaves this "specific to each relay" — a flat `"admin"`
role holding every moderation permission this build implements. An
embedder that wants real multi-role policies calls
`GroupsService.SetModerationPolicy` to replace it. `kind:9008`'s
admin-gate (Phase 1) was migrated onto this same `CanPerform` path instead
of staying its own one-off "is any kind of admin" check.

`kind:9021` group-scoped join has no pending-approval queue: an open group
(`Metadata.Closed == false`) admits any request outright; a closed one
needs a valid, single-use `kind:9009` invite code (see Phase 3) in the
request's `code` tag, or it's refused with "ask an admin" — the admin's own
`kind:9000` put-user is the only other path in. The spec doesn't define a
request/approval-queue event shape, so this build doesn't invent one.

## Phase 3 — implemented

Metadata/invites/pins: `kind:9002` → `39000`, `kind:9009` (group-scoped
invites, separate store from NIP-43's own invite store), `kind:9010` →
`39005`, `kind:9005` moderator delete.

Shipped shape: `kind:9002` edit-metadata replaces `GroupRecord.Metadata`
wholesale (the event carries the complete desired access-flag state, same
"absolute list" convention `kind:9010` already used for pins) rather than
patching individual fields. `kind:9009` invites persist in their own bbolt
bucket (`indexGroupInvites` in `relay/store_groups.go`), keyed by
`groupID\x00code`; a code carries no TTL or max-uses (the kind:9009 event
itself has nowhere to put them per `nip29.NewCreateInvite`'s shape), so
each is simply valid once. `kind:9005` moderator delete does not reuse
NIP-09's own kind:5 deletion path (`relay/store.go`'s `insert()`), which is
author-scoped by design (`delEvent.PubKey != event.PubKey` skips); a group
admin needs to delete *any* member's event, so this goes through
`EventStore.FindEvents` + `DeleteAll` directly, gated only by confirming
the target event's own `h` tag names the admin's group.

One implementation-level fix that fell out of testing this: the relay's
own `kind:39000`/`39001`/`39002`/`39005` mirror events are NIP-33
parameterized-replaceable, and two republishes of the same kind for the
same group within the same wall-clock second hit NIP-01's own tie-break
(lowest event id wins on an exact `created_at` match, unrelated to actual
recency) — which could silently leave a group's publicly-visible state
stuck on stale content even though `GroupsService`'s authoritative bbolt
record updated correctly. `mirrorCreatedAt` in `relay/groups.go` bumps a
republish's `created_at` past whatever is already stored for that
kind+group before signing, sidestepping the tie entirely.

## Explicitly out of scope, all phases

No new `ncli relay groups create` admin command. Per NIP-29, creating a group
is a self-service client action (anyone publishes their own signed `9007`),
not an operator gate like NIP-43 enrollment. `ncli id sign` + `ncli publish`
already suffice once Phase 1 ships.

## Reference prior art

`block/buzz`'s `crates/buzz-admin/src/main.rs` `ReconcileChannels` subcommand
(kind:39000/39001/39002 discovery-event backfill/reconciliation) is useful
prior art for shape, even though it's a different codebase on a different
relay-wide-vs-group-scoped membership model — don't port its Redis-roster-push
mechanism (nmilat has no Redis dependency and shouldn't gain one for this;
use the existing bbolt + in-memory cache pattern instead).
