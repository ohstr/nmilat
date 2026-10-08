# Relay benchmarks

Latency and cost of the flows a relay serves every day, under a
production-like load on a store much larger than RAM.

## Setup

| | |
|---|---|
| Store | 9.2 GiB bbolt, 3.9M events, 3,000 authors: 68% kind 1, 20% kind 7, 7% kind 1059, plus kind 0/3/10002 |
| Relay | 4 CPUs, 860 MiB memory (store 11× RAM, like relay.ohstr.com), cold page cache |
| Limits | `max_limit` 500, `max_subscriptions` 20 |
| Clients | 70 new connections per 30s, each open 60–180s (~290 open at once) |
| Per connection | a feed and a notifications REQ kept open, an id lookup and a profile lookup |
| Writes | 5 events/s (kind 1, with some 1059 and ephemeral 20001) |
| Measured | 4 minutes, after 2 minutes of warmup |

## Reading and writing

p50 / p99. `next` is rc.12 plus the live-tail fix
([CHANGELOG](../CHANGELOG.md)).

| Flow | Request | rc.12 | next |
|---|---|---|---|
| Open a feed | `{"kinds":[1],"limit":100}` until EOSE | 18.5 s / 51.7 s | 6.5 ms / 12 ms |
| Notifications | `{"kinds":[1,7],"#p":[<me>],"limit":50}` until EOSE | 24.6 s / 42.7 s | 19 ms / 47 ms |
| Notes by id | `{"ids":[5 ids]}` until EOSE | 7.9 s / 10.8 s | 7 ms / 13 ms |
| Profiles | `{"kinds":[0],"authors":[10 pubkeys]}` until EOSE | 8.0 s / 10.8 s | 2.5 ms / 10 ms |
| Publish a note | kind 1 `EVENT` until `OK` | 49 ms / 111 ms | 15 ms / 63 ms |
| Publish a DM | kind 1059 `EVENT` until `OK` | 49 ms / 108 ms | 16 ms / 56 ms |
| Publish ephemeral | kind 20001 `EVENT` until `OK` | 55 ms / 102 ms | 15 ms / 54 ms |
| Live delivery | published note reaching ~290 open feeds | 4.9 s / 37.6 s | 23 ms / 71 ms |

No REQ timed out (60s) or was closed in either run.

## Cost

| | rc.12 | next |
|---|---|---|
| CPU (of 4) | 304% | 26% |
| Memory | 860 MiB (at limit) | 423 MiB |
| Disk reads | 18.4 MB/s | 0.7 MB/s |
| Major page faults | 4,622/s | 165/s |
| I/O pressure (avg10) | 20% | 0.9% |
| REQs waiting for a scan slot | 615 (avg) | 0 |

## What changed

- Open subscriptions read only new events instead of re-walking their
  whole index every 50ms (rc.12's cause of read starvation).
- A REQ that waits more than 10s for a scan slot gets `CLOSED`
  `error: relay busy, try again later` instead of no answer
  (`WithEventStoreScanSlotWait`).
- Subscriptions wake when a write commits instead of polling.

## Run it

```sh
CGO_ENABLED=0 go build -o relayload-next ./cmd/relayload
./relayload-next gen -db notes.db -events 3900000
RELAYLOAD_DIR=$PWD sh cmd/relayload/run.sh next
```

`run.sh` needs Docker and caps the relay at 860 MiB, sized for this
store. Results land in `results/next.summary.json`, with a CPU profile
beside it. Build `relayload-<name>` from another commit to compare.
