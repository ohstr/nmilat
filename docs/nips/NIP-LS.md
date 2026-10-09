NIP-LS
======

Local Signer: NIP-46 over a Unix Socket
---------------------------------------

`draft` `optional`

**Depends on**: [NIP-01](https://github.com/nostr-protocol/nips/blob/master/01.md), [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md)

## Abstract

A signer process holds a key and answers the NIP-46 method set for other processes on the same host, over a unix socket. Requests and responses are NIP-46's JSON objects, one per line, with no relay, no encryption and no wrapping event. The socket's file permissions decide who may connect; the signer's own policy decides what it signs.

## Motivation

NIP-46 moves the key out of the client, but it routes every call through a relay and encrypts it, because client and signer are assumed to be on different machines. When they share a machine or a pod — an AI agent and a sidecar holding its key, a CI job and a signing daemon — the relay is a needless dependency and a round trip of hundreds of milliseconds, and NIP-44 adds nothing the kernel doesn't already give. A process that can't read the key file can still sign, but only what the signer's policy allows.

## Addressing

A signer is addressed by a URI:

```
bunker+unix:///abs/path/to/signer.sock
```

- The path MUST be absolute and MUST NOT carry a query or fragment.
- Clients SHOULD also accept `unix:///abs/path` and MAY accept a bare absolute path.
- Clients SHOULD accept this URI wherever they accept a `bunker://` URI.

## Wire format

The client connects to the socket and writes requests; the signer writes one response per request, in order, on the same connection.

- Each message is one UTF-8 JSON object followed by `\n`.
- A request is NIP-46's request object: `{"id": "<string>", "method": "<string>", "params": ["<string>", ...]}`.
- A response is NIP-46's response object: `{"id": "<request id>", "result": "<string>"}` or `{"id": "<request id>", "error": "<string>"}`.
- A message, newline excluded, MUST NOT exceed 1 MiB. A signer MAY close a connection that sends a longer one.
- Blank lines are ignored. A line that is not a JSON object gets a response with an empty `id` and an `invalid: ` error.
- A connection carries any number of requests. Clients that pipeline requests MUST match responses by `id`; a signer MAY answer requests on one connection strictly in order.

## Methods

The NIP-46 method set, with these differences:

| Method | Behavior |
|--------|----------|
| `sign_event` | `params[0]` is the unsigned event JSON. The signer sets `pubkey` to its own (refusing an event that names a different one), computes `id`, and returns the signed event JSON. `params[1]`, if present and non-empty, is a JSON array of events the signer's policy may require as attestations (see below). |
| `get_public_key` | Returns the signer's pubkey (hex). |
| `ping` | Returns `pong`. |
| `nip04_encrypt`, `nip04_decrypt`, `nip44_encrypt`, `nip44_decrypt` | As NIP-46: `params` are `[counterpart-pubkey, text]`. |
| `connect`, `logout` | Accepted and answered `ack`. There is no session: the socket's permissions are the session. |
| `get_relays` | Returns `{}`. |
| `switch_relays` | Returns `null`. |

A signer MAY implement further methods, named so they don't collide with NIP-46's (e.g. `signer_status`).

## Errors

An `error` string starting with one of these prefixes classifies the failure so a client can act on it without parsing the rest:

| Prefix | Meaning | Client should |
|--------|---------|---------------|
| `denied: ` | The policy (or a built-in safety check) refused the request. | Treat as a refusal, not a transport failure; don't retry unchanged. |
| `invalid: ` | The request was malformed or the method unknown. | Fix the request. |

The text after the prefix is a human-readable reason. Any other error string is a failure while carrying out an allowed request.

## Attestations

A policy may require a third party's signed approval before signing — for example, a maintainer's kind-1 note reading `approve <event id>`. The client passes such events as a JSON array in `sign_event`'s `params[1]`. The event they approve is identified by the `id` the signer computes for `params[0]` after setting its own pubkey, which the client can compute in advance. What makes an attestation valid is the signer's policy, not this NIP.

## Signer requirements

- The signer MUST refuse to sign an event, or encrypt a plaintext, that contains its own private key in any encoding it knows (hex, `nsec`, the `ncryptsec` it was loaded from), regardless of policy.
- The signer SHOULD create the socket with restrictive permissions (e.g. `0600` or `0660` with a dedicated group) and SHOULD NOT replace an existing non-socket file or a symlink at its path.
- On platforms that expose peer credentials (`SO_PEERCRED`), the signer MAY restrict connections to listed uids or gids.
- The signer SHOULD default to denying any `sign_event` or encrypt/decrypt request its policy doesn't explicitly allow.

## Client requirements

- After `sign_event`, the client SHOULD verify the returned event's signature and check that its `kind`, `content`, `created_at` and `tags` equal what it sent and its `pubkey` equals the signer's.
- If a client abandons a request (timeout, cancellation), the connection's response stream is out of step; the client SHOULD close it and reconnect.

## Security Considerations

- There is no authentication beyond the socket's file permissions and optional peer-credential checks. Anyone who can connect can ask; the policy decides what they get.
- The protocol carries no encryption. It MUST NOT be exposed over a network transport.
- A policy that consumes one-time state (attestations, quotas) must make "check, spend, sign" atomic, or two concurrent requests can spend the same approval.

## Reference Implementation

[`github.com/ohstr/nmilat/nipLS`](../../nipLS): `Dial`/`Client` for the client side, `NewServer` with a pluggable `Policy` for the signer side. [`ncli signer serve`](https://github.com/ohstr/ncli) runs a signer with a YAML policy.
