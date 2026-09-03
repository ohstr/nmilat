package nipcash

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"

	"github.com/ohstr/nmilat/nipAZ"
	"github.com/ohstr/nmilat/nipIC"
)

// Recipient is who mint_cash funds a slice for — build one with Pubkey,
// ConnectionKey, or Anyone. No identity_type string ever appears in caller
// code: each constructor encodes its own wire shape internally.
type Recipient interface {
	// recipient is an unexported marker: only types this package constructs
	// satisfy Recipient, so a caller can never hand-roll one.
	recipient()
}

// Target is who CashTransfer/CashConsolidate reassigns a slice to: a
// pubkey- or connection_key-identified Recipient built with Pubkey/
// ConnectionKey, or a *BearerTarget for the bearer case. Anyone() does NOT
// satisfy Target — see BearerTarget's own doc comment for why mint_cash's
// and cash_transfer's bearer cases need genuinely different credential-
// generation semantics, not just a naming difference. Passing Anyone()
// where a Target is expected is a compile error, not a runtime one.
type Target interface {
	// target is an unexported marker: only types this package constructs
	// satisfy Target, so a caller can never hand-roll one.
	target()
}

// namedIdentity is Pubkey's and ConnectionKey's concrete Recipient/Target —
// a Nostr pubkey or a nipIC.ConnectionKey (via nipAZ.Identity), never
// bearer. It's the only concrete type that satisfies both Recipient (valid
// as a mint_cash allocation) and Target (valid as a cash_transfer/
// cash_consolidate new_identity) — unlike bearerRecipient (Anyone()), which
// only ever satisfies Recipient.
type namedIdentity struct {
	identity nipAZ.Identity
	ia       string // Identity Authority pubkey, "" unless connection_key mode
}

func (namedIdentity) recipient() {}
func (namedIdentity) target()    {}

func (n namedIdentity) identityType() string {
	if n.identity.WebIdentity() != "" {
		return identityTypeConnectionKey
	}
	return identityTypePubkey
}
func (n namedIdentity) identityValue() string { return n.identity.Value() }
func (n namedIdentity) iaPubkey() string      { return n.ia }

// Pubkey builds a Recipient/Target for a native Nostr identity.
func Pubkey(hex string) namedIdentity {
	return namedIdentity{identity: nipAZ.Pubkey(hex)}
}

// ConnectionKey builds a Recipient/Target for a Web Identity account that
// has no Nostr keypair yet, vouched for by the Identity Authority at
// iaPubkey — platform+externalID are hashed into a nipIC.ConnectionKey
// internally (via nipAZ.Connection, itself built on nipIC.NewConnectionKey),
// so no caller ever computes that hash by hand.
func ConnectionKey(platform nipIC.WebIdentity, externalID, iaPubkey string) namedIdentity {
	return namedIdentity{identity: nipAZ.Connection(platform, externalID), ia: iaPubkey}
}

// bearerRecipient is Anyone()'s concrete Recipient — plain cash, no
// registered identity, redeemable by whoever holds the wallet's secret.
// Deliberately satisfies only Recipient, not Target: see BearerTarget.
type bearerRecipient struct{}

func (bearerRecipient) recipient()            {}
func (bearerRecipient) identityType() string  { return identityTypeBearer }
func (bearerRecipient) identityValue() string { return "" }
func (bearerRecipient) iaPubkey() string      { return "" }

// Anyone builds a Recipient for plain, unbound cash — the Hub mints its
// bearer secret and returns it once, in MintCash's own response
// (MintCashResult.Recipients[i].BearerSecret). Not usable as a
// CashTransfer/CashConsolidate Target — use NewBearerTarget for that case
// instead, which has different, caller-side secret-generation requirements.
func Anyone() Recipient { return bearerRecipient{} }

// BearerTarget is a not-yet-realized bearer identity, used only as a
// CashTransfer/CashConsolidate Target. It is NOT the same as Anyone():
// mint_cash's bearer recipient gets its secret minted by the Hub, over the
// Hub's own single-owner connection — safe to return in that response.
// cash_transfer's bearer target is the opposite: NIP-CASH requires the
// *caller* to generate the secret and submit only its commitment, because
// the response travels back over the shared *source* connection,
// decryptable by every co-recipient it's ever had (NIP-CASH §Security
// Considerations — an implementation that minted a fresh secret here and
// handed it back would leak it to exactly the audience this mechanism
// exists to keep it from). NewBearerTarget generates that secret locally —
// it never appears in any request or response — and exposes it via Secret
// so the caller can hand it to whoever they're transferring to, alongside
// the returned wallet token.
type BearerTarget struct {
	secret string
	commit string // hex sha256(secret) — the value actually sent on the wire
}

func (*BearerTarget) target() {}

// NewBearerTarget generates a fresh, high-entropy bearer secret locally and
// its commitment, ready to use as a CashTransfer/CashConsolidate Target.
func NewBearerTarget() *BearerTarget {
	var raw [32]byte
	// crypto/rand.Read never returns a partial read without an error on any
	// platform Go supports; a non-nil error here means the platform's CSPRNG
	// is unavailable, which nothing downstream could recover from either.
	if _, err := rand.Read(raw[:]); err != nil {
		panic("nipcash: crypto/rand unavailable: " + err.Error())
	}
	sum := sha256.Sum256(raw[:])
	return &BearerTarget{secret: hex.EncodeToString(raw[:]), commit: hex.EncodeToString(sum[:])}
}

// Secret returns the bearer secret to hand to whoever this target's
// CashTransfer/CashConsolidate call is for — alongside the call's own
// returned wallet token, since neither alone is redeemable.
func (t *BearerTarget) Secret() string { return t.secret }

func (t *BearerTarget) identityType() string  { return identityTypeBearer }
func (t *BearerTarget) identityValue() string { return t.commit }
func (t *BearerTarget) iaPubkey() string      { return "" }

// Allocation pairs a Recipient with the amount mint_cash funds their slice
// with. Build one with Send.
type Allocation struct {
	Recipient    Recipient
	AmountMillis uint64
}

// Send pairs recipient with amountMillis for MintCash's batch call.
func Send(recipient Recipient, amountMillis uint64) Allocation {
	return Allocation{Recipient: recipient, AmountMillis: amountMillis}
}

// Source pairs a source wallet with its own current committed amount and
// the Credential proving control over it, for CashConsolidate. Build one
// with From — a live Credential (BySigning; connection_key/bearer sources
// are rejected by this revision of NIP-CASH, see ErrBearerSource), or one
// built from a proof captured earlier via ByProof. Authorization is
// per-source, not per-connection, so a relayer holding only captured
// proofs can still consolidate on someone else's behalf (NIP-CASH
// §Consolidating Tokens).
type Source struct {
	WalletPubkey string
	// Amount is this source's own current committed amount, in millis —
	// REQUIRED: like CashTransferParams.CurrentAmount, each source's proof
	// must bind to its own concrete amount, which this package can't infer
	// on its own. Get this from a prior mint_cash/cash_transfer response or
	// ListRecipients.
	Amount     uint64
	Credential Credential
}

// From pairs walletPubkey and its current amount with a Credential.
func From(walletPubkey string, amount uint64, cred Credential) Source {
	return Source{WalletPubkey: walletPubkey, Amount: amount, Credential: cred}
}

// Credential proves the caller's control over a slice's current registered
// identity (or, for a bearer slice, presents its secret) when redeeming,
// transferring, or consolidating. Build one with BySecret, BySigning, or
// BySigningConnectionKey — never implement this interface directly.
type Credential interface {
	// buildProof produces this credential's identity_type/identity_value
	// (empty for a bearer credential — the server looks the slice up by
	// bearer_secret instead) and its proof for one specific call, bound via
	// binding to that call's own wallet/invoice/target/amount.
	// identityEvent is the kind-23198 claim proof (nil for a bearer
	// credential, which has no identity to sign with); attestationEvent is
	// the kind-35522 IA attestation to send alongside it (only for
	// connection_key mode); bearerSecret is the plaintext secret (only for
	// a bearer credential). Exactly one of {identityEvent, bearerSecret} is
	// ever set.
	buildProof(binding proofBinding) (identityType, identityValue string, identityEvent, attestationEvent []byte, bearerSecret string, err error)

	// decryptDelivery decrypts a spun-off wallet's *_wallet_token field
	// (NIP-CASH §Spinning a Slice Off Into a Dedicated Wallet): a NIP-44
	// payload keyed to this credential's own real identity privkey and
	// newWalletPubkey (the spun-off wallet's own pubkey). Only signing
	// credentials have a privkey to derive that key from; a bearer
	// credential returns ciphertext unchanged (a bearer-current caller's
	// proof carries no pubkey to derive a delivery key from, so the spec
	// requires this case deliver in the clear instead — see NIP-CASH
	// §Spinning a Slice Off's own "bearer-current caller" paragraph).
	decryptDelivery(newWalletPubkey, ciphertext string) (string, error)
}
