package nipcash

import (
	"errors"
	"fmt"

	"github.com/ohstr/nmilat/utils"
)

var (
	// ErrClaimNotFound is a bill that has no row for the caller: the Hub answered
	// NOT_FOUND, or a scope-all roster holds none of the caller's rows.
	ErrClaimNotFound = errors.New("nipcash: this bill has no slice for the caller")
	// ErrMineWidened is a mine answer that is not exactly the caller's one row: a
	// Hub MUST NOT widen it.
	ErrMineWidened = errors.New("nipcash: a scope-mine answer is not exactly the caller's row")
	// ErrRowAmbiguous is a scope-all roster with two unclaimed rows for the
	// caller's identity: an identity holds at most one live slice of a wallet, so
	// which one is the caller's cannot be told.
	ErrRowAmbiguous = errors.New("nipcash: a scope-all answer has two unclaimed rows for the caller")
)

// OwnRow finds the caller's row, taking the identity from the credential, never
// from the caller's word: a signing credential's pubkey matches a pubkey row; a
// connection_key credential matches its key and its IA; a cash credential
// matches the cash row its secret commits to. With scope mine (or empty) the
// answer must be exactly that row (ErrMineWidened otherwise). With all, which
// lists every slice the wallet ever had, claimed history included, it is the
// caller's unclaimed row wherever it is listed (ErrRowAmbiguous for two), else
// the most recently claimed of its rows, else ErrClaimNotFound.
func OwnRow(rows []RecipientStatus, cred Credential, scope string) (RecipientStatus, error) {
	match, err := rowMatcher(cred)
	if err != nil {
		return RecipientStatus{}, err
	}
	if scope == "" || scope == ScopeMine {
		if len(rows) != 1 || !match(rows[0]) {
			return RecipientStatus{}, fmt.Errorf("%w: %d rows", ErrMineWidened, len(rows))
		}
		return rows[0], nil
	}
	var live, latest *RecipientStatus
	for i := range rows {
		r := &rows[i]
		switch {
		case !match(*r):
		case !r.Claimed:
			if live != nil {
				return RecipientStatus{}, ErrRowAmbiguous
			}
			live = r
		case latest == nil || claimedAt(*r) > claimedAt(*latest):
			latest = r
		}
	}
	switch {
	case live != nil:
		return *live, nil
	case latest != nil:
		return *latest, nil
	}
	return RecipientStatus{}, ErrClaimNotFound
}

// claimedAt is a claimed row's claimed_at, 0 when it carries none.
func claimedAt(r RecipientStatus) int64 {
	if r.ClaimedAt == nil {
		return 0
	}
	return *r.ClaimedAt
}

func rowMatcher(cred Credential) (func(RecipientStatus) bool, error) {
	switch c := cred.(type) {
	case signingCredential:
		pub, err := utils.GetPublicKey(c.privKeyHex)
		if err != nil {
			return nil, err
		}
		return func(r RecipientStatus) bool { return r.IdentityType == identityTypePubkey && r.IdentityValue == pub }, nil
	case connectionKeyCredential:
		key, ia := string(c.attestation.ConnectionKey), c.attestation.PubKey
		return func(r RecipientStatus) bool {
			return r.IdentityType == identityTypeConnectionKey && r.IdentityValue == key && r.IAPubkey == ia
		}, nil
	case secretCredential:
		commit, err := CashCommitment(c.secret)
		if err != nil {
			return nil, err
		}
		return func(r RecipientStatus) bool {
			return r.IdentityType == identityTypeCash && CommitmentsEqual(r.IdentityValue, commit)
		}, nil
	}
	return nil, errors.New("nipcash: no identity to match a row by")
}

// Claimable reports whether a row can still be spent at now, and if not why:
// claimed, withdrawn (a cash_withdraw ended it) or expired.
func Claimable(row RecipientStatus, now int64) (ok bool, reason string) {
	switch {
	case row.Claimed:
		return false, "claimed"
	case row.WithdrawRequestID != "":
		return false, "withdrawn"
	case !SliceLive(now, row.ExpiresAt.ptr()):
		return false, "expired"
	}
	return true, ""
}

// CheckClaimResult is the caller's own row, whether it can be spent, and the
// bill's verified minter (x-only, empty without a verified provenance).
type CheckClaimResult struct {
	Row         RecipientStatus
	Claimable   bool
	Reason      string
	MinterXOnly string
}
