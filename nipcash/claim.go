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
)

// OwnRow finds the caller's row, taking the identity from the credential, never
// from the caller's word: a signing credential's pubkey matches a pubkey row; a
// connection_key credential matches its key and its IA; a cash credential
// matches the cash row its secret commits to. With scope mine (or empty) the
// answer must be exactly that row (ErrMineWidened otherwise); with all, the
// matching row, else ErrClaimNotFound.
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
	for _, r := range rows {
		if match(r) {
			return r, nil
		}
	}
	return RecipientStatus{}, ErrClaimNotFound
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
