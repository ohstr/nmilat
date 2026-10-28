package client

import (
	"context"
	"sort"

	"github.com/ohstr/nmilat/nipcash"
)

// Unreconciled reads j's calls not yet closed (written ahead, never reconciled
// with a decided answer) and lists those holding a secret the user would
// lose with them: a generated cash secret (PendingCall.Secrets) or an order's
// buyer key. NIP-CASH §Security Considerations for Cash-Mode Slices: an
// implementation SHOULD surface any unreconciled secret to its user.
//
// Calls are returned oldest deadline first, as copies. A call whose RequestID is
// not a valid request_id (nipcash.ValidRequestID) is listed too: it cannot be
// looked up, so its secret is not a complete recovery path and MUST NOT be
// presented as one. A nil j is ErrNoJournal. Nothing is sent.
func (c *Client) Unreconciled(ctx context.Context, j interface {
	Unreconciled(context.Context) ([]nipcash.PendingCall, error)
}) ([]nipcash.PendingCall, error) {
	if j == nil {
		return nil, ErrNoJournal
	}
	calls, err := j.Unreconciled(ctx)
	if err != nil {
		return nil, err
	}
	var out []nipcash.PendingCall
	for _, pc := range calls {
		if len(pc.Secrets) == 0 && pc.BuyerKey == "" {
			continue
		}
		pc.Secrets = append([]nipcash.PendingSecret(nil), pc.Secrets...)
		out = append(out, pc)
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Deadline < out[b].Deadline })
	return out, nil
}
