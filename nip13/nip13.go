// Package nip13 implements NIP-13: Proof of Work, letting an event embed a
// nonce tag whose event ID has a target number of leading zero bits. It
// operates on plain event fields (Fields) rather than a concrete event
// type, so it has no dependency on nip01 — nip01 depends on nip13 (to
// validate PoW during Event.Verify), and a dependency back the other way
// would be a cycle.
package nip13

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ohstr/nmilat/nip13/sha256"
	"github.com/ohstr/nmilat/utils"
)

const (
	POWTagName = "nonce"
)

// Fields is the minimal set of event fields nip13 needs to mine or validate
// a proof-of-work nonce. ID is required by ValidatePow (the value being
// checked) and ignored by Mine (which produces one instead); Sig is required
// by Mine's must-be-unsigned guard and ignored by ValidatePow.
type Fields struct {
	ID        string
	PubKey    string
	CreatedAt uint64
	Kind      int
	Tags      [][]string
	Content   string
	Sig       string
}

func countZerosFromHex(hexStr string) (count int, err error) {
	if len(hexStr) != 64 {
		err = fmt.Errorf("invalid key, bad size: %d", len(hexStr))
		return
	}

	var bytes []byte
	bytes, err = hex.DecodeString(hexStr)
	if err != nil {
		return
	}

	count = countZerosFromBytes(bytes)
	return
}

func countZerosFromBytes(bytes []byte) (count int) {

	for _, b := range bytes {
		if b == 0 {
			count += 8
			continue
		}
		for i := 7; i >= 0; i-- {
			if (b>>i)&1 == 0 {
				count++
			} else {
				return
			}
		}
	}
	return
}

// hashID computes the NIP-01 event ID hash for ev, mirroring
// nip01.Event.HashID's serialization exactly (duplicated here, rather than
// imported, to keep this package dependency-free of nip01).
func hashID(ev Fields) ([]byte, error) {
	tagsBytes, err := utils.MarshalTags(ev.Tags)
	if err != nil {
		return nil, err
	}

	str := fmt.Appendf(nil, "[0,\"%s\",%d,%d,", strings.ToLower(ev.PubKey), ev.CreatedAt, ev.Kind)
	str = append(str, tagsBytes...)
	str = append(str, ',')
	str = fmt.Appendf(str, `"%s"`, utils.EscapeJSONString(ev.Content))
	str = append(str, ']')

	hsh := sha256.Sum256(str)

	return hsh[:], nil
}

// Progress reports mining progress aggregated across every worker, for a
// caller that registered WithProgress.
type Progress struct {
	HashesTried uint64
	Elapsed     time.Duration
	Workers     int
}

type mineConfig struct {
	workers  int
	progress func(Progress)
	interval time.Duration
}

// MineOption configures Mine's search strategy (parallelism, progress
// reporting). The zero value of every option is "off" -- Mine with no
// options behaves exactly as it did before options existed.
type MineOption func(*mineConfig)

// WithWorkers searches for a valid nonce across n goroutines in parallel,
// each covering a disjoint stride of the nonce space (worker i tries
// nonce=i, i+n, i+2n, ...). n<=0 means 1, which reproduces the original
// single-threaded search (nonce=0,1,2,...) exactly -- Mine's default with no
// options at all.
func WithWorkers(n int) MineOption {
	return func(c *mineConfig) { c.workers = n }
}

// WithProgress calls fn roughly every interval (default 3s if interval<=0)
// with the hash count and elapsed time aggregated across all workers, until
// Mine returns.
func WithProgress(interval time.Duration, fn func(Progress)) MineOption {
	return func(c *mineConfig) { c.progress, c.interval = fn, interval }
}

type nonceResult struct {
	nonce uint64
	id    string
}

// mineWorker searches nonce=startNonce, startNonce+stride, startNonce+2*
// stride, ... for one that gives prefix+nonce+suffix a hash with at least
// targetDifficulty leading zero bits, sending the first one found on found
// (buffered, so this never blocks past a done ctx) and returning either way
// once ctx is cancelled. It keeps computeNonce's original optimization of
// writing prefix into the digest once and cloning it (via Sum) per attempt,
// rather than rehashing the whole prefix every time.
func mineWorker(ctx context.Context, prefix, suffix []byte, targetDifficulty int, startNonce, stride uint64, tried *atomic.Uint64, found chan<- nonceResult) {
	hash := sha256.New()
	hash.Write(prefix)

	nonce := startNonce
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		idBytes := hash.Sum(append([]byte(strconv.FormatUint(nonce, 10)), suffix...))
		tried.Add(1)

		if countZerosFromBytes(idBytes) >= targetDifficulty {
			select {
			case found <- nonceResult{nonce: nonce, id: hex.EncodeToString(idBytes)}:
			case <-ctx.Done():
			}
			return
		}

		nonce += stride
	}
}

// computeNonceParallel orchestrates cfg.workers (at least 1) mineWorker
// goroutines over disjoint nonce strides, returning as soon as any one of
// them finds a match and cancelling the rest. With cfg.workers<=1 this
// searches nonce=0,1,2,... on a single goroutine, identical in order and
// hashing strategy to the original sequential computeNonce.
func computeNonceParallel(ctx context.Context, prefix, suffix []byte, targetDifficulty int, cfg *mineConfig) (nonce uint64, id string, err error) {
	workers := max(cfg.workers, 1)

	workerCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	var tried atomic.Uint64
	found := make(chan nonceResult, workers)

	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(start uint64) {
			defer wg.Done()
			mineWorker(workerCtx, prefix, suffix, targetDifficulty, start, uint64(workers), &tried, found)
		}(uint64(i))
	}

	var progressDone chan struct{}
	if cfg.progress != nil {
		progressDone = make(chan struct{})
		interval := cfg.interval
		if interval <= 0 {
			interval = 3 * time.Second
		}
		go func() {
			defer close(progressDone)
			start := time.Now()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-workerCtx.Done():
					return
				case <-ticker.C:
					cfg.progress(Progress{HashesTried: tried.Load(), Elapsed: time.Since(start), Workers: workers})
				}
			}
		}()
	}

	select {
	case res := <-found:
		nonce, id = res.nonce, res.id
	case <-ctx.Done():
		err = errors.New("mining cancelled")
	}

	cancel()
	wg.Wait()
	if progressDone != nil {
		<-progressDone
	}
	return
}

// ValidatePow checks ev's nonce tag against its actual ID: that the nonce
// tag is well-formed, that ev.ID has at least as many leading zero bits as
// the tag's declared difficulty, and that ev.ID is in fact the correct hash
// of ev's other fields (i.e. the nonce wasn't just copied from a different
// event).
func ValidatePow(ev Fields) (nonce string, difficulty int, err error) {

	nonces, ok := utils.LookupEventTag(ev.Tags, POWTagName)
	if !ok {
		err = fmt.Errorf("nonce tag not found, %v", nonces)
		return
	}

	if len(nonces) > 1 {
		err = fmt.Errorf("more than one nonce provided %v", nonces)
		return
	}

	nonceTag := nonces[0]
	if len(nonceTag) != 3 {
		err = fmt.Errorf("invalid length %d", len(nonceTag))
		return
	}

	difficulty, err = strconv.Atoi(nonceTag[2])
	if err != nil {
		return
	}

	var zeros int
	zeros, err = countZerosFromHex(ev.ID)
	if err != nil {
		return
	}

	if zeros < difficulty {
		err = fmt.Errorf("insufficient proof of work: nonce tag declares difficulty %d but event ID only has %d leading zero bits", difficulty, zeros)
		return
	}

	var eventIDBytes []byte
	eventIDBytes, err = hashID(ev)
	if err != nil {
		return
	}

	if eventID := hex.EncodeToString(eventIDBytes); eventID != ev.ID {
		err = fmt.Errorf("mismatched event ID: want %s, got %s", ev.ID, eventID)
		return
	}

	nonce = nonceTag[1]
	return
}

// Mine finds a nonce tag that gives ev an ID with at least targetDifficulty
// leading zero bits, per NIP-13. It returns the new ID and the nonce tag to
// append; the caller applies both to its own event (Mine has no event type
// to mutate). ev must be unsigned — mining after signing would invalidate
// the signature, since it changes the ID.
func Mine(ctx context.Context, ev Fields, targetDifficulty int, opts ...MineOption) (id string, nonceTag []string, err error) {

	if len(ev.Sig) > 0 {
		err = errors.New("event must not be signed")
		return
	}

	if err = utils.Validate32Key(ev.PubKey); err != nil {
		err = fmt.Errorf("invalid pubkey `%s`, %w", ev.PubKey, err)
		return
	}

	if err = utils.ValidateKind(ev.Kind); err != nil {
		err = fmt.Errorf("invalid kind `%d`, %w", ev.Kind, err)
		return
	}

	if nonces, ok := utils.LookupEventTag(ev.Tags, POWTagName); ok {
		err = fmt.Errorf("nonce tag already present, %v", nonces)
		return
	}

	tags := ev.Tags
	if tags == nil {
		tags = [][]string{}
	}

	var tagsBytes []byte
	tagsBytes, err = utils.MarshalTags(tags)
	if err != nil {
		return
	}

	prefixTags := tagsBytes[:len(tagsBytes)-1] // remove the last ]
	if len(tags) > 0 {
		prefixTags = append(prefixTags, ',')
	}
	prefixTags = fmt.Appendf(prefixTags, `["%s","`, POWTagName)  // ["nonce","
	suffixTags := fmt.Appendf(nil, `","%d"]]`, targetDifficulty) // ","difficulty"]

	prefix := fmt.Appendf(nil, "[0,\"%s\",%d,%d,", strings.ToLower(ev.PubKey), ev.CreatedAt, ev.Kind)
	prefix = append(prefix, prefixTags...)

	suffix := fmt.Appendf(suffixTags, `,"%s"]`, utils.EscapeJSONString(ev.Content))

	var cfg mineConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	nonceVal, id, err := computeNonceParallel(ctx, prefix, suffix, targetDifficulty, &cfg)
	if err != nil {
		return "", nil, err
	}

	nonceTag = []string{POWTagName, strconv.FormatUint(nonceVal, 10), strconv.Itoa(targetDifficulty)}

	return id, nonceTag, nil
}
