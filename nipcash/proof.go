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
// bearerRecipient, *BearerTarget) implements this unexported shape
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

// --- BySecret: bearer credential ---

type secretCredential struct{ secret string }

// BySecret proves control of a bearer slice by presenting its secret — the
// entire proof, exactly as NIP-CASH's own bearer redemption model requires.
func BySecret(secret string) Credential { return secretCredential{secret: secret} }

func (c secretCredential) buildProof(proofBinding) (identityType, identityValue string, identityEvent, attestationEvent []byte, bearerSecret string, err error) {
	return "", "", nil, nil, c.secret, nil
}

// decryptDelivery is a pass-through: a bearer-current caller's proof is
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

func (c signingCredential) buildProof(binding proofBinding) (identityType, identityValue string, identityEvent, attestationEvent []byte, bearerSecret string, err error) {
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

func (c connectionKeyCredential) buildProof(binding proofBinding) (identityType, identityValue string, identityEvent, attestationEvent []byte, bearerSecret string, err error) {
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

func (c connectionKeyCredential) decryptDelivery(newWalletPubkey, ciphertext string) (string, error) {
	return decryptFromPubkey(c.privKeyHex, newWalletPubkey, ciphertext)
}

// --- ByProof: a proof captured earlier, not built from a live signing key ---

type proofCredential struct {
	identityEvent []byte
	identityValue string // parsed from identityEvent's own "pubkey" field
}

// ByProof builds a Credential from a kind-23198 proof captured earlier —
// e.g. by a relayer/service consolidating several sources on someone else's
// behalf, holding only proofs each source's real owner signed and handed
// over out of band, never their private keys (NIP-CASH §Consolidating
// Tokens: authorization is per-source, not per-connection). identityEventJSON
// is the same JSON-encoded event BySigning would have produced; this
// revision of cash_consolidate only accepts pubkey-identified sources, so
// the proof's own signer pubkey is both its identity_value and the
// verification the server needs — nothing else to derive.
func ByProof(identityEventJSON []byte) (Credential, error) {
	var ev struct {
		PubKey string `json:"pubkey"`
	}
	if err := json.Unmarshal(identityEventJSON, &ev); err != nil {
		return nil, fmt.Errorf("nipcash: parse captured proof: %w", err)
	}
	if ev.PubKey == "" {
		return nil, fmt.Errorf("nipcash: captured proof has no pubkey")
	}
	return proofCredential{identityEvent: identityEventJSON, identityValue: ev.PubKey}, nil
}

func (c proofCredential) buildProof(proofBinding) (identityType, identityValue string, identityEvent, attestationEvent []byte, bearerSecret string, err error) {
	return identityTypePubkey, c.identityValue, c.identityEvent, nil, "", nil
}

func (proofCredential) decryptDelivery(string, string) (string, error) {
	return "", errors.New("nipcash: a ByProof credential has no private key and cannot decrypt a delivery")
}
