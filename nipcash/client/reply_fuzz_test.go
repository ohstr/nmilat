package client

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// FuzzCollectReply is F-REPLY-1: collectReply over arbitrary chunk sets. A decided,
// non-conflicted outcome is never lost, nothing panics, and the collection ends when
// the stream does.
//
// The input is read as up to six chunks. Per chunk: seq, total, a flag byte (bit 0 an
// envelope-level error, bit 1 no results field, bit 2 a foreign req_nonce), a result
// count, then two bytes per result: the item (0-3, or 4 for an id never sent) and its
// kind (0 a matching result, 1 a wrong result_type, 2 an error).
func FuzzCollectReply(f *testing.F) {
	f.Add([]byte{1, 1, 0, 2, 0, 0, 1, 2})
	f.Add([]byte{1, 2, 0, 1, 0, 0, 2, 3, 0, 1, 0, 0})
	f.Add([]byte{1, 2, 1, 0, 2, 2, 0, 1, 1, 0})
	f.Add([]byte{0, 0, 2, 0, 5, 2, 0, 2, 4, 0, 3, 1})
	ids := []string{"a", "b", "c", "d"}
	f.Fuzz(func(t *testing.T, data []byte) {
		nonce := strings.Repeat("ab", 32)
		var key [32]byte
		copy(key[:], strings.Repeat("f", 32))
		p := statusPacked(nonce, 0, ids...)

		next := func() int {
			if len(data) == 0 {
				return 0
			}
			b := int(data[0])
			data = data[1:]
			return b
		}
		type answer struct{ kind int }
		perID := map[string][]answer{}
		envErrs := 0
		var events []*nip01.Event
		for c := 0; c < 6 && len(data) > 0; c++ {
			seq, total, flags, n := next()%5, next()%5, next(), next()%6
			reqNonce := nonce
			if flags&4 != 0 {
				reqNonce = strings.Repeat("cd", 32)
			}
			var parts []string
			for i := 0; i < n; i++ {
				idx, kind := next()%5, next()%3
				id := "alien"
				if idx < 4 {
					id = ids[idx]
				}
				switch kind {
				case 0:
					parts = append(parts, fmt.Sprintf(`{"id":%q,"result_type":"cash_status","result":{}}`, id))
				case 1:
					parts = append(parts, fmt.Sprintf(`{"id":%q,"result_type":"cash_redeem","result":{}}`, id))
				default:
					parts = append(parts, fmt.Sprintf(`{"id":%q,"error":{"code":"NOT_FOUND"}}`, id))
				}
				if reqNonce == nonce && flags&2 == 0 && idx < 4 {
					perID[id] = append(perID[id], answer{kind})
				}
			}
			body := fmt.Sprintf(`{"req_nonce":%q,"seq":%d,"total":%d`, reqNonce, seq, total)
			if flags&1 != 0 {
				body += `,"error":{"code":"RATE_LIMITED"}`
				if reqNonce == nonce {
					envErrs++
				}
			}
			if flags&2 == 0 {
				body += `,"results":[` + strings.Join(parts, ",") + `]`
			}
			body += "}"
			sealed, err := nip44.Encrypt(body, key[:])
			if err != nil {
				t.Fatal(err)
			}
			events = append(events, &nip01.Event{ID: fmt.Sprint(c), Content: sealed})
		}

		ch := make(chan *nip01.Event, len(events))
		for _, ev := range events {
			ch <- ev
		}
		close(ch)
		s := hostileSession(transport.DefaultLimits(), strings.Repeat("b", 64))
		// collectReply stops at the first complete set, so later chunks may go unread:
		// it must terminate without a panic and give one outcome per item.
		if got, _ := s.collectReply(context.Background(), ch, key, p, 0); got != nil && len(got) != len(ids) {
			t.Fatalf("%d outcomes for %d items", len(got), len(ids))
		}

		// The decision itself, over every chunk: a decided answer is never lost.
		state := newReplyState(p)
		for _, ev := range events {
			pt, err := nip44.Decrypt(ev.Content, key[:])
			if err != nil {
				t.Fatal(err)
			}
			chunk, err := transport.DecodeResponseChunk([]byte(pt), nonce, ids, 0)
			if err != nil {
				continue
			}
			state.add(ev.ID, chunk)
		}
		got, _ := state.outcomes(0)
		if len(got) != len(ids) {
			t.Fatalf("%d outcomes for %d items", len(got), len(ids))
		}
		for _, o := range got {
			as := perID[o.ID]
			if len(as) != 1 || envErrs != 0 {
				continue
			}
			switch as[0].kind {
			case 0:
				if o.State != OutcomeResult || !json.Valid(o.Result) {
					t.Fatalf("%s: decided result lost: %+v", o.ID, o)
				}
			case 2:
				if o.State != OutcomeError || o.Error == nil || o.Error.Code != "NOT_FOUND" {
					t.Fatalf("%s: decided error lost: %+v", o.ID, o)
				}
			default:
				if o.State != OutcomeConflict {
					t.Fatalf("%s: wrong result_type accepted: %+v", o.ID, o)
				}
			}
		}
	})
}
