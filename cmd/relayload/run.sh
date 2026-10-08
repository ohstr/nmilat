#!/bin/sh
# One cold-cache run of relayload-<variant> against a copy of notes.db:
# serve pinned to 4 CPUs with ~1/11 of the store's size in memory (prod's
# ratio), load unconstrained. Results land in results/<variant>.*.
#
# usage: run.sh <variant> [load flags...]
set -e
V=$1
shift
# Directory holding notes.db, its sample file and relayload-<variant> binaries.
D=${RELAYLOAD_DIR:-$PWD}
cd "$D"
mkdir -p results
docker rm -f rl-serve >/dev/null 2>&1 || true
cp notes.db run.db
"./relayload-$V" evict -db run.db
docker network create relayload >/dev/null 2>&1 || true
docker run -d --name rl-serve --network relayload --cpuset-cpus 0-3 --memory 860m --memory-swap 860m \
  -v "$D:/w" -w /w alpine:3 "./relayload-$V" serve -db run.db >/dev/null
sleep 5
docker logs rl-serve
# CPU profile and goroutine dump from inside the run.
(sleep 150
 docker run --rm --network relayload -v "$D/results:/r" alpine:3 \
   wget -q -O "/r/$V.cpu.pprof" "http://rl-serve:7448/debug/pprof/profile?seconds=30"
 docker run --rm --network relayload -v "$D/results:/r" alpine:3 \
   wget -q -O "/r/$V.goroutines.txt" "http://rl-serve:7448/debug/pprof/goroutine?debug=1") &
docker run --rm --network relayload -v "$D:/w" -w /w alpine:3 "./relayload-$V" load \
  -url ws://rl-serve:7447 -stats http://rl-serve:7448/stats -sample notes.db.sample.json \
  -out "results/$V.summary.json" "$@" > "results/$V.log" 2>&1
wait
docker logs rl-serve > "results/$V.serve.log" 2>&1
docker rm -f rl-serve >/dev/null
rm -f run.db
tail -n 60 "results/$V.log"
