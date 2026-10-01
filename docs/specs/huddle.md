# Huddle protocol

Real-time voice for a NIP-53 room, served by the relay that hosts the room.

A relay advertises a huddle in the room's kind:30312 `service` tag. Two
endpoints carry the same room: a binary WebSocket for native clients, and a
WebRTC/SFU endpoint for browsers. Both share one room, so peers on either
endpoint hear each other.

This document is the wire contract. It is written so a client that has never
seen this implementation can join media. Normative keywords are RFC 2119.

## 1. Endpoints

```
wss://<relay>/huddle/<room-id>/rtc      WebRTC (SFU) -- browsers
wss://<relay>/huddle/<room-id>/audio    binary WebSocket -- native clients
```

`<room-id>` is the room's identifier: the `d` tag of the kind:30312 event. The
`service` tag names the `/rtc` form.

Both endpoints are separate from the relay's Nostr WebSocket, deliberately. The
Nostr socket decodes every frame as JSON, so a binary audio frame arriving there
is a parse error that tears the session down. Audio therefore gets its own route
and its own upgrader.

A relay MAY serve neither endpoint. One that cannot serve audio MUST refuse with
`huddle_audio_unavailable` rather than admit a peer to a room that can never
carry its voice.

## 2. Control plane

Control messages are JSON **objects** on the same WebSocket — again unlike the
Nostr socket, which uses JSON arrays. A client MUST ignore unknown `type`
values and unknown object fields.

### 2.1 Handshake (both endpoints)

```
server -> {"type":"challenge","challenge":"..."}
client -> {"type":"auth","event":{...},"protocol_version":3}
server -> {"type":"joined","revision":N,"pubkey":"...","peer_index":N,"epoch":N,"peers":[...]}
```

The server sends `challenge` immediately on connect. The client MUST answer with
`auth` within the server's auth timeout (5 s in this implementation) or be
disconnected.

On success the joiner receives `joined`. Every other peer in the room receives
the same `joined` object, so a client learns about arrivals without polling.

### 2.2 Roster changes

```
server -> {"type":"left","pubkey":"...","peer_index":N,"epoch":N,"revision":N}
```

Broadcast to the remaining peers when someone leaves.

### 2.3 WebRTC negotiation (`/rtc` only)

```
client -> {"type":"offer","sdp":"..."}
server -> {"type":"answer","sdp":"..."}
server -> {"type":"offer","sdp":"..."}     renegotiation: a new speaker was added
client -> {"type":"answer","sdp":"..."}
both   -> {"type":"candidate","candidate":{...}}
```

The **client offers first**, because it owns the microphone. The server offers
only to add a newly-heard speaker's track, and the client MUST answer. ICE
candidates flow both ways and MAY arrive before or after the answer.

### 2.4 Errors

```
server -> {"type":"error","code":"...","message":"..."}
```

`message` is for humans and MAY change. `code` is the contract:

| code | meaning |
|---|---|
| `auth_failed` | authentication failed. Deliberately does not say why, so the endpoint cannot be used to probe what a relay knows. |
| `join_rejected` | authentication succeeded, but this pubkey may not join this room. |
| `room_full` | the room is at participant capacity. |
| `room_ended` | the huddle is over. |
| `upgrade_required` | the room is pinned to a protocol version the client did not ask for. `current_version` names the room's. |
| `room_unavailable` | the relay already hosts as many rooms as it will. |
| `huddle_audio_unavailable` | this deployment does not serve huddle audio. |
| `negotiation_failed` | `/rtc` only: the WebRTC handshake itself failed, as distinct from being refused admission. |

A client SHOULD branch on `code` and MUST tolerate an unknown one.

## 3. Authentication

The `auth` message carries a NIP-42 event (kind 22242). The server checks:

- **kind** is 22242.
- **`created_at`** is within 10 minutes of the server's clock, either direction.
- a **`challenge` tag** equal to the challenge the server just sent.
- a **`relay` tag** equal to the relay's own base WebSocket URL, compared as an
  **exact string**.
- the event signature.

The `relay` tag is the **relay's** URL, not the huddle endpoint's: a client
authenticates to the relay, then uses that identity here. It MUST match the
relay's NIP-11 `url` byte for byte — no trailing-slash or scheme normalisation
is applied, so a client that guesses the form will be refused with
`auth_failed`.

Admission is a second, separate decision. A relay MAY gate a room on membership
(NIP-43) or on its own per-room policy; refusal is `join_rejected`. Admission
MUST NOT be derived from anything in the audio frames (see §5).

### 3.1 Revocation

A relay MAY evict a peer whose right to be in the room is withdrawn while it is
connected. Eviction sends `error` with `join_rejected` and closes that peer's
socket; the other peers stay up and receive the ordinary `left` broadcast. A
client MUST NOT assume that passing admission once keeps it in the room.

## 4. Peers, indexes and epochs

`joined` and `left` carry three identifiers:

- **`pubkey`** — the authenticated identity.
- **`peer_index`** — a small integer (one byte, 255 values) the relay assigns
  for the life of the peer's membership. It is what the audio routing prefix
  carries instead of a 32-byte pubkey.
- **`epoch`** — how many times that index has been handed out. When a peer
  leaves, its index becomes available again but the epoch is **not** reset, so
  `(peer_index, epoch)` distinguishes the new occupant of an index from the old
  one. A client MUST key its decoder state on the pair, not on the index alone.

`revision` increases on every roster change. A client MAY use it to discard a
roster view it has already superseded. A room holds at most 25 peers.

## 5. Media

### 5.1 Audio format

Every frame carries exactly one 20 ms Opus packet, 48 kHz, mono — 960 samples.

### 5.2 Protocol versions

A client names the version it wants in `auth`. A room **pins** whichever version
its first peer asked for; a later peer that does not match is refused with
`upgrade_required` rather than fed frames it would misparse. Versions 1 through 3
are defined, 3 is current, and a client that names none is assumed to want 1, so
clients predating version negotiation keep working. Older versions stay
supported indefinitely so a rollout can be staged.

### 5.3 Client frame header

From protocol version 2 onward each client frame begins with an 8-byte header,
network byte order, followed by the opaque Opus payload:

```
byte 0..=1 : Seq        uint16
byte 2..=5 : Ts48k      uint32
byte 6     : LevelDbov  int8   range [-127, 0]
byte 7     : Flags      uint8  bit 0 = DTX; other bits reserved
```

Reserved `Flags` bits MUST be ignored by a receiver and MUST be round-tripped
untouched rather than masked off, so a future flag survives an intermediate hop.
`-127` is the canonical "no signal" level; an out-of-range level is clamped into
range rather than causing the frame to be dropped.

### 5.4 Relayed frame prefix

When the relay fans a frame out it prepends a routing prefix and forwards the
client's bytes verbatim:

| version | prefix |
|---|---|
| 1, 2 | 1 byte: `peer_index` |
| 3 | 2 bytes: `peer_index`, `epoch` |

The prefix is routing metadata only; it never touches the client's frame bytes.

### 5.5 Opaque payloads

The Opus payload is **never** decoded, re-encoded or rewritten by the relay. A
relay parses the header for telemetry and to reject frames that are clearly
malformed for the room's pinned version, then forwards the bytes as they
arrived. On `/rtc` the payload is repacketized between RTP and huddle frames —
still without being decoded. This is what lets a relay carry audio without
linking a codec, and it means a relay is an SFU, never a mixer.

### 5.6 Telemetry is untrusted

`LevelDbov` is client-authored. Anything derived from it — logs, active-speaker
hints, dominant-talker decisions — MUST treat it as untrusted. Trust decisions
(admission, moderation, eviction) MUST NOT consume it.

## 6. Liveness

The server pings on an interval (30 s here) and drops a peer that stops
answering after a small number of missed pongs (3 here). A client MUST answer
WebSocket pings.

## 7. Relationship to NIP-29

NIP-29's audio/video section assumes LiveKit: a client fetches a JWT from
`/.well-known/nip29/livekit/<group-id>` using NIP-98 authorisation, and the
relay decides admission by issuing or withholding that token.

Huddle keeps that model — **the relay decides admission** — but not its
mechanism. There is no token endpoint: admission is decided over NIP-42 on the
media WebSocket itself, which keeps the identity that authenticates to the relay
and the identity that joins the room the same object, and avoids a second
credential format with its own lifetime. A client implementing both will share
its NIP-42 code and none of its token code.
