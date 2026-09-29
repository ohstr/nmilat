package nipcash

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/nipIC"
	"github.com/ohstr/nmilat/utils"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
)

// decryptFromPubkey decrypts a NIP-44 payload keyed to privKeyHex (this
// caller's own real identity key) and pubKeyHex (the spun-off wallet's own
// pubkey) — the same derivation nip47's own encrypted-response handling
// uses (schnorr.ParsePubKey for the 32-byte x-only nostr pubkey,
// nip44.GenerateConversationKey, nip44.Decrypt).
func decryptFromPubkey(privKeyHex, pubKeyHex, ciphertext string) (string, error) {
	privBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return "", fmt.Errorf("nipcash: invalid private key: %w", err)
	}
	priv, _ := btcec.PrivKeyFromBytes(privBytes)
	pubBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return "", fmt.Errorf("nipcash: invalid public key: %w", err)
	}
	pub, err := schnorr.ParsePubKey(pubBytes)
	if err != nil {
		return "", fmt.Errorf("nipcash: invalid public key: %w", err)
	}
	key, err := nip44.GenerateConversationKey(priv, pub)
	if err != nil {
		return "", fmt.Errorf("nipcash: derive delivery key: %w", err)
	}
	plaintext, err := nip44.Decrypt(ciphertext, key)
	if err != nil {
		return "", fmt.Errorf("nipcash: decrypt delivery: %w", err)
	}
	return plaintext, nil
}

// ErrAttestationExpired is returned when a connection_key Credential's
// nipIC.Attestation carries no expiration, or one that has already passed.
// nipIC.ParseAttestation itself treats expiration as optional, because
// NIP-IC supports revoking a single attestation directly (a NIP-09 kind-5
// deletion). NIP-CASH's target server has no per-attestation revocation —
// only whole-Identity-Authority revocation — so it requires a mandatory,
// unexpired expiration as its only bound on how long a compromised
// attestation stays honorable, and rejects one carrying neither. This
// credential enforces that same rule client-side, before ever building a
// request that the server would reject anyway.
var ErrAttestationExpired = errors.New("nipcash: attestation has no expiration, or has already expired")


// proofBinding carries the call-specific values a kind-23198 proof binds to,
// beyond the wallet pubkey every proof binds to via its own d-tag. Exactly
// one of Bolt11Hash (cash_redeem) or NewIdentityHash+AmountMillis
// (cash_transfer/cash_consolidate) is set, matching NIP-CASH's own binding
// rules per method.
type proofBinding struct {
	WalletPubkey    string
	Bolt11Hash      string
	NewIdentityHash string
	AmountMillis    *uint64
}

func (b proofBinding) tags() [][]string {
	tags := [][]string{{"d", b.WalletPubkey}}
	if b.Bolt11Hash != "" {
		tags = append(tags, []string{"bolt11_hash", b.Bolt11Hash})
	}
	if b.NewIdentityHash != "" {
		tags = append(tags, []string{"new_identity_hash", b.NewIdentityHash})
	}
	if b.AmountMillis != nil {
		tags = append(tags, []string{"amount_millis", fmt.Sprintf("%d", *b.AmountMillis)})
	}
	return tags
}

// targetFields narrows a Target (or Recipient) back to its identity_type/
// identity_value/ia_pubkey triple — every concrete implementer (namedIdentity,
// cashRecipient, *CashTarget) implements this unexported shape
// internally; the type assertion is safe because neither interface has an
// implementer outside this package (their marker methods are unexported).
type targetFields interface {
	identityType() string
	identityValue() string
	iaPubkey() string
}

// newIdentityHash computes NIP-CASH's own new_identity_hash binding:
// sha256(identity_type + ":" + identity_value + ":" + ia_pubkey), hex-
// encoded. Both cash_transfer's/cash_consolidate's own new_identity tag and
// this package's proof-building use this so they always agree byte-for-byte.
func newIdentityHash(t Target) string {
	f := t.(targetFields)
	sum := sha256.Sum256([]byte(f.identityType() + ":" + f.identityValue() + ":" + f.iaPubkey()))
	return hex.EncodeToString(sum[:])
}

// --- BySecret: cash credential ---

type secretCredential struct{ secret string }

// BySecret proves control of a cash-mode slice by presenting its secret — the
// entire proof, exactly as NIP-CASH's own cash-mode redemption model requires.
func BySecret(secret string) Credential { return secretCredential{secret: secret} }

func (c secretCredential) buildProof(proofBinding) (identityType, identityValue string, identityEvent, attestationEvent []byte, cashSecret string, err error) {
	return "", "", nil, nil, c.secret, nil
}

// itemAuthorization: cash-mode, so there is no key and no proof — the secret
// itself authorizes the item (NIP-CASH §Bearer Items).
func (c secretCredential) itemAuthorization() (privKeyHex, cashSecret string, err error) {
	return "", c.secret, nil
}

// decryptDelivery is a pass-through: a cash-mode caller's proof is
// their raw secret, which carries no pubkey to derive a delivery key from,
// so NIP-CASH requires this case be delivered in the clear instead — see
// Credential's own doc comment.
func (secretCredential) decryptDelivery(_, ciphertext string) (string, error) {
	return ciphertext, nil
}

// --- BySigning: pubkey credential ---

type signingCredential struct{ privKeyHex string }

// BySigning proves control of a Nostr-pubkey-identified slice by signing a
// fresh kind-23198 proof internally — the caller supplies a key, never
// builds or signs an event themselves.
func BySigning(privKeyHex string) Credential { return signingCredential{privKeyHex: privKeyHex} }

func (c signingCredential) buildProof(binding proofBinding) (identityType, identityValue string, identityEvent, attestationEvent []byte, cashSecret string, err error) {
	pubkey, err := utils.GetPublicKey(c.privKeyHex)
	if err != nil {
		return "", "", nil, nil, "", fmt.Errorf("nipcash: derive pubkey: %w", err)
	}
	ev, err := nip01.NewSignedEvent(KindClaimProof, "", c.privKeyHex, binding.tags()...)
	if err != nil {
		return "", "", nil, nil, "", fmt.Errorf("nipcash: sign claim proof: %w", err)
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return "", "", nil, nil, "", fmt.Errorf("nipcash: marshal claim proof: %w", err)
	}
	return identityTypePubkey, pubkey, raw, nil, "", nil
}

func (c signingCredential) decryptDelivery(newWalletPubkey, ciphertext string) (string, error) {
	return decryptFromPubkey(c.privKeyHex, newWalletPubkey, ciphertext)
}

// itemAuthorization: a plain signing identity, so the transport signs a
// kind-23192 with this key.
func (c signingCredential) itemAuthorization() (privKeyHex, cashSecret string, err error) {
	return c.privKeyHex, "", nil
}

// --- BySigningConnectionKey: connection_key credential ---

type connectionKeyCredential struct {
	privKeyHex  string
	platform    nipIC.WebIdentity
	externalID  string
	attestation *nipIC.Attestation
}

// BySigningConnectionKey proves control of a connection_key-identified
// slice: privKeyHex signs the kind-23198 proof (the caller's own real
// Nostr identity, once they have one), and attestation is the IA's
// kind-35522 attestation — parsed once with nipIC.ParseAttestation and
// reused here, not a raw JSON blob this package invents its own shape for.
// buildProof enforces NIP-CASH's stricter mandatory-and-unexpired
// expiration rule on top of nipIC's own, more permissive parse — see
// ErrAttestationExpired.
func BySigningConnectionKey(privKeyHex string, platform nipIC.WebIdentity, externalID string, attestation *nipIC.Attestation) Credential {
	return connectionKeyCredential{privKeyHex: privKeyHex, platform: platform, externalID: externalID, attestation: attestation}
}

func (c connectionKeyCredential) buildProof(binding proofBinding) (identityType, identityValue string, identityEvent, attestationEvent []byte, cashSecret string, err error) {
	if c.attestation == nil || c.attestation.ExpiresAt == nil || time.Now().After(*c.attestation.ExpiresAt) {
		return "", "", nil, nil, "", ErrAttestationExpired
	}
	connectionKey := nipIC.NewConnectionKey(c.platform, c.externalID)
	tags := append(binding.tags(),
		[]string{"connection_key", connectionKey.String()},
		[]string{"e", c.attestation.ID},
	)
	ev, err := nip01.NewSignedEvent(KindClaimProof, "", c.privKeyHex, tags...)
	if err != nil {
		return "", "", nil, nil, "", fmt.Errorf("nipcash: sign claim proof: %w", err)
	}
	identityEvent, err = json.Marshal(ev)
	if err != nil {
		return "", "", nil, nil, "", fmt.Errorf("nipcash: marshal claim proof: %w", err)
	}
	attestationEvent, err = json.Marshal(c.attestation.Event)
	if err != nil {
		return "", "", nil, nil, "", fmt.Errorf("nipcash: marshal attestation: %w", err)
	}
	return identityTypeConnectionKey, connectionKey.String(), identityEvent, attestationEvent, "", nil
}

// itemAuthorization: a connection_key identity signs with its own real Nostr key,
// exactly as it does for a claim proof. The IA attestation is NOT returned here — it
// travels in the item's params alongside identity_type/identity_value, the same way
// it does on the standard transport, because it authenticates the identity rather
// than the envelope.
//
// The expiry check buildProof performs is deliberately not repeated. A stale
// attestation must fail where it is actually used, against the request that carries
// it, rather than here where the error could only say "some credential is stale".
func (c connectionKeyCredential) itemAuthorization() (privKeyHex, cashSecret string, err error) {
	return c.privKeyHex, "", nil
}

func (c connectionKeyCredential) decryptDelivery(newWalletPubkey, ciphertext string) (string, error) {
	return decryptFromPubkey(c.privKeyHex, newWalletPubkey, ciphertext)
}

