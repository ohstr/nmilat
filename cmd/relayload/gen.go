package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand/v2"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/relay"
	"golang.org/x/sys/unix"
)

// sample is what gen leaves next to the store for load to query with.
type sample struct {
	Authors []string `json:"authors"`
	IDs     []string `json:"ids"`
}

func authorKey(i int) string {
	h := sha256.Sum256(fmt.Appendf(nil, "relayload-author-%d", i))
	return hex.EncodeToString(h[:])
}

var words = strings.Fields("nostr relay zap note bitcoin lightning gm pv meme art photo music " +
	"freedom protocol client key sign event feed follow reply thread today tomorrow " +
	"build ship test bench cache disk index query fast slow good great hello world")

func content(r *rand.Rand, n int) string {
	var b strings.Builder
	for b.Len() < n {
		b.WriteString(words[r.IntN(len(words))])
		b.WriteByte(' ')
	}
	return b.String()
}

func randHex(r *rand.Rand, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return hex.EncodeToString(b)
}

func runGen(args []string) error {
	fs := flag.NewFlagSet("gen", flag.ExitOnError)
	db := fs.String("db", "notes.db", "store path")
	total := fs.Int("events", 1_000_000, "events to generate")
	nAuthors := fs.Int("authors", 3000, "distinct authors")
	span := fs.Duration("span", 2*365*24*time.Hour, "created_at spread, ending now")
	seed := fs.Uint64("seed", 1, "rng seed")
	_ = fs.Parse(args)

	lim := &nip11.Limitation{MaxLimit: 500}
	store, err := relay.NewEventStore(*db, lim)
	if err != nil {
		return err
	}
	defer store.Close()

	r := rand.New(rand.NewPCG(*seed, 0))
	keys := make([]string, *nAuthors)
	pubs := make([]string, *nAuthors)
	for i := range keys {
		keys[i] = authorKey(i)
		ev := nip01.NewEvent(0, "")
		if err := ev.Sign(keys[i]); err != nil {
			return err
		}
		pubs[i] = ev.PubKey
	}
	// A few accounts post most of the notes.
	zipf := rand.NewZipf(r, 1.1, 8, uint64(*nAuthors-1))

	type job struct {
		ev  *nip01.Event
		key string
	}
	jobs := make(chan job, 4096)
	signed := make(chan *nip01.Event, 4096)

	go func() {
		defer close(jobs)
		end := uint64(time.Now().Add(-time.Hour).Unix())
		start := end - uint64(span.Seconds())
		step := float64(end-start) / float64(*total)
		for i := 0; i < *total; i++ {
			// Seed every author's profile, follows and relay list first.
			var a int
			var kind int
			if i < 3**nAuthors {
				a, kind = i/3, []int{0, 3, 10002}[i%3]
			} else {
				a = int(zipf.Uint64())
				switch p := r.IntN(1000); {
				case p < 680:
					kind = 1
				case p < 880:
					kind = 7
				case p < 950:
					kind = 1059
				case p < 970:
					kind = 3
				case p < 985:
					kind = 0
				default:
					kind = 10002
				}
			}
			created := start + uint64(float64(i)*step)
			// Ingest from many relays delivers some events late.
			if r.IntN(100) < 5 {
				created -= uint64(r.IntN(30 * 24 * 3600))
			}
			ev := nip01.NewEvent(kind, "")
			ev.Tags = [][]string{}
			ev.CreatedAt = created
			other := pubs[r.IntN(len(pubs))]
			switch kind {
			case 1:
				ev.Content = content(r, 40+r.IntN(600))
				if r.IntN(10) < 3 {
					ev.Tags = [][]string{{"e", randHex(r, 32)}, {"p", other}}
				}
			case 7:
				ev.Content = "+"
				ev.Tags = [][]string{{"e", randHex(r, 32)}, {"p", other}, {"k", "1"}}
			case 1059:
				raw := make([]byte, 700+r.IntN(1500))
				for j := range raw {
					raw[j] = byte(r.Uint32())
				}
				ev.Content = base64.StdEncoding.EncodeToString(raw)
				ev.Tags = [][]string{{"p", other}}
			case 0:
				ev.Content = fmt.Sprintf(`{"name":"user%d","about":%q}`, a, content(r, 80))
			case 3:
				n := 50 + r.IntN(250)
				for j := 0; j < n; j++ {
					ev.Tags = append(ev.Tags, []string{"p", pubs[r.IntN(len(pubs))]})
				}
			case 10002:
				ev.Tags = [][]string{{"r", "wss://relay.ohstr.com"}, {"r", "wss://relay.damus.io"}, {"r", "wss://nos.lol", "read"}}
			}
			jobs <- job{ev, keys[a]}
		}
	}()

	var swg sync.WaitGroup
	for w := 0; w < runtime.NumCPU(); w++ {
		swg.Add(1)
		go func() {
			defer swg.Done()
			for j := range jobs {
				if err := j.ev.Sign(j.key); err == nil {
					signed <- j.ev
				}
			}
		}()
	}
	go func() { swg.Wait(); close(signed) }()

	smp := sample{Authors: pubs}
	const keepIDs = 20000
	var seen int
	tasks := make(chan []*nip01.Event, 8)
	var iwg sync.WaitGroup
	var insertErr error
	var errOnce sync.Once
	for w := 0; w < 4; w++ {
		iwg.Add(1)
		go func() {
			defer iwg.Done()
			for evs := range tasks {
				t := relay.NewEventInsertTask(evs)
				store.Execute(context.Background(), t)
				select {
				case <-t.Completed():
				case err := <-t.Errors():
					if !errors.Is(err, relay.ErrEventDuplicated) {
						errOnce.Do(func() { insertErr = err })
					}
				}
			}
		}()
	}

	began := time.Now()
	batch := make([]*nip01.Event, 0, 500)
	for ev := range signed {
		if ev.Kind == 1 || ev.Kind == 7 {
			// Reservoir sample of ids to query by later.
			seen++
			if len(smp.IDs) < keepIDs {
				smp.IDs = append(smp.IDs, ev.ID)
			} else if j := r.IntN(seen); j < keepIDs {
				smp.IDs[j] = ev.ID
			}
		}
		batch = append(batch, ev)
		if len(batch) == cap(batch) {
			tasks <- batch
			batch = make([]*nip01.Event, 0, 500)
		}
	}
	if len(batch) > 0 {
		tasks <- batch
	}
	close(tasks)
	iwg.Wait()
	if insertErr != nil {
		return insertErr
	}

	out, _ := json.Marshal(smp)
	if err := os.WriteFile(*db+".sample.json", out, 0o644); err != nil {
		return err
	}
	fi, _ := os.Stat(*db)
	var size int64
	if fi != nil {
		size = fi.Size()
	}
	fmt.Printf("generated %d events in %s, db %.2f GiB (%d B/event)\n",
		*total, time.Since(began).Round(time.Second), float64(size)/(1<<30), size/int64(*total))
	return nil
}

// runEvict drops the store from the page cache so serve starts cold.
func runEvict(args []string) error {
	fs := flag.NewFlagSet("evict", flag.ExitOnError)
	db := fs.String("db", "notes.db", "store path")
	_ = fs.Parse(args)
	f, err := os.Open(*db)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED)
}
