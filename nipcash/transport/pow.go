package transport

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip13"
)

// MaxPowAhead bounds a mined request's expiration: at most one day ahead.
const MaxPowAhead = 86400

var (
	// ErrPowDifficulty is a proof-of-work target below 1 (send without PoW then).
	ErrPowDifficulty = errors.New("transport: proof-of-work difficulty must be at least 1")
	// ErrPowDeadline is a not_after more than MaxPowAhead seconds ahead.
	ErrPowDeadline = errors.New("transport: a mined request's expiration is at most one day ahead")
)

// PowRequest is a mined kind-23190. Event is what to publish; the ephemeral key
// is kept so Remine can mine it again after a relay asks for more work.
type PowRequest struct {
	Event   *nip01.Event
	privHex string
}

// WrapRequestPow builds the request exactly as WrapRequest does, adds
// ["expiration", "<notAfter>"], mines it to difficulty under ctx and signs it
// (NIP-CASH §Proof of Work). It returns the conversation key like WrapRequest.
func WrapRequestPow(ctx context.Context, plaintext []byte, inboxXOnly string, notAfter int64, difficulty int) (*PowRequest, [32]byte, error) {
	var key [32]byte
	if difficulty < 1 {
		return nil, key, ErrPowDifficulty
	}
	if notAfter > time.Now().Unix()+MaxPowAhead {
		return nil, key, fmt.Errorf("%w: %d", ErrPowDeadline, notAfter)
	}
	ev, privHex, key, err := buildRequest(plaintext, inboxXOnly)
	if err != nil {
		return nil, key, err
	}
	ev.Tags = append(ev.Tags, []string{"expiration", strconv.FormatInt(notAfter, 10)})
	r := &PowRequest{Event: ev, privHex: privHex}
	if err := r.mine(ctx, difficulty); err != nil {
		return nil, key, err
	}
	return r, key, nil
}

// Remine mines the same request again to difficulty: same key, content,
// created_at, p and expiration tags, a new nonce tag, re-signed. The envelope
// inside is unchanged, so a Hub that already ran it drops the copy at E3.
func (r *PowRequest) Remine(ctx context.Context, difficulty int) error {
	if difficulty < 1 {
		return ErrPowDifficulty
	}
	kept := r.Event.Tags[:0:0]
	for _, tag := range r.Event.Tags {
		if len(tag) > 0 && tag[0] == nip13.POWTagName {
			continue
		}
		kept = append(kept, tag)
	}
	r.Event.Tags, r.Event.Sig, r.Event.ID = kept, "", ""
	return r.mine(ctx, difficulty)
}

func (r *PowRequest) mine(ctx context.Context, difficulty int) error {
	if err := r.Event.Mine(ctx, difficulty); err != nil {
		return fmt.Errorf("transport: mine request: %w", err)
	}
	if err := r.Event.Sign(r.privHex); err != nil {
		return fmt.Errorf("transport: sign request: %w", err)
	}
	if got, err := nip13.Difficulty(r.Event.ID); err != nil || got < difficulty {
		return fmt.Errorf("transport: mined id has difficulty %d, want %d", got, difficulty)
	}
	return nil
}

// ParsePowRejection reads a relay's OK message: ok when it starts "pow:", with
// the difficulty it names ("pow: difficulty 20 required"), 0 when it names none.
func ParsePowRejection(okMsg string) (difficulty int, ok bool) {
	if !strings.HasPrefix(okMsg, "pow:") {
		return 0, false
	}
	for _, f := range strings.Fields(okMsg[4:]) {
		if n, err := strconv.Atoi(f); err == nil && n > 0 {
			return n, true
		}
	}
	return 0, true
}
