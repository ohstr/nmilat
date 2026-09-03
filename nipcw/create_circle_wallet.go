package nipcw

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"

	"github.com/ohstr/nmilat/nip44"
)

// CreateCircleWalletParams is create_circle_wallet's friendly request —
// self-service request for the caller's own Circle Wallet.
type CreateCircleWalletParams struct {
	Credential Credential
	// MaxAmountMillis is the requested spend cap, MUST NOT exceed the Hub's
	// own per-wallet ceiling. NIP-CW's own wire field is the un-suffixed
	// "max_amount" — it predates, and was deliberately left out of,
	// NIP-CASH's own coin-agnostic "_millis" rename, since a circle isn't
	// coin-agnostic today (NIP-CW §Non-Goals). The Go field here is still
	// named MaxAmountMillis for terminology consistency with nipcash at the
	// SDK layer only — that naming choice doesn't change the wire contract.
	MaxAmountMillis uint64
	// Expiry is OPTIONAL. Zero means "use the Hub's own expiry ceiling."
	Expiry time.Duration
	// BudgetRenewal is OPTIONAL ("daily"/"weekly"/"monthly"/"yearly"/
	// "never"). Empty means "use the Hub's own default (never)." Whether
	// omitted or explicit, the resolved value MUST satisfy the Hub's own
	// renewal floor (NIP-CW §Budget Renewal Floor).
	BudgetRenewal string
}

// CreateCircleWalletRequest is create_circle_wallet's wire request shape.
type CreateCircleWalletRequest struct {
	Pubkey        string `json:"pubkey"`
	MaxAmount     uint64 `json:"max_amount"`
	Expiry        int    `json:"expiry"`
	BudgetRenewal string `json:"budget_renewal,omitempty"`
	IdentityEvent string `json:"identity_event"`
}

// Request builds create_circle_wallet's wire request from p, bound to
// hubPubkey (the Circle Wallet Hub connection's own pubkey — nipcw/client
// supplies this). Exported for nipcw/client's use; a caller using
// nipcw/client's CreateCircleWallet method never calls this directly.
func (p CreateCircleWalletParams) Request(hubPubkey string) (CreateCircleWalletRequest, error) {
	pubkey, err := p.Credential.pubkey()
	if err != nil {
		return CreateCircleWalletRequest{}, err
	}
	proof, err := p.Credential.buildProof(hubPubkey)
	if err != nil {
		return CreateCircleWalletRequest{}, err
	}
	return CreateCircleWalletRequest{
		Pubkey:        pubkey,
		MaxAmount:     p.MaxAmountMillis,
		Expiry:        int(p.Expiry / time.Second),
		BudgetRenewal: p.BudgetRenewal,
		IdentityEvent: string(proof),
	}, nil
}

// createCircleWalletResponseWire is create_circle_wallet's raw wire
// response — EncryptedPairingURI is still NIP-44 encrypted at this point;
// ParseResult decrypts it into CreateCircleWalletResponse's PairingURI.
type createCircleWalletResponseWire struct {
	EncryptedPairingURI string `json:"encrypted_pairing_uri"`
	WalletPubkey        string `json:"wallet_pubkey"`
	ExpiresAt           int64  `json:"expires_at"`
	FeesPpm             int    `json:"fees_ppm"`
	BudgetRenewal       string `json:"budget_renewal"`
}

// CreateCircleWalletResponse is create_circle_wallet's response, with
// PairingURI already decrypted — connect straight from it.
type CreateCircleWalletResponse struct {
	PairingURI    string
	WalletPubkey  string
	ExpiresAt     int64
	FeesPpm       int
	BudgetRenewal string
}

// ParseResult parses create_circle_wallet's wire response, decrypting
// encrypted_pairing_uri with p.Credential's own privkey (the response is
// NIP-44 encrypted to the requester's own pubkey — NIP-CW §Creating a
// Circle Wallet — so no other holder of the shared Hub connection,
// including the Hub owner, can read it). Exported for nipcw/client's use;
// a caller using nipcw/client's CreateCircleWallet method never calls this
// directly.
func (p CreateCircleWalletParams) ParseResult(hubPubkey string, data []byte) (*CreateCircleWalletResponse, error) {
	var wire createCircleWalletResponseWire
	if err := json.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	pairingURI, err := decryptFromPubkey(p.Credential.privKeyHex, hubPubkey, wire.EncryptedPairingURI)
	if err != nil {
		return nil, fmt.Errorf("nipcw: decrypt pairing uri: %w", err)
	}
	return &CreateCircleWalletResponse{
		PairingURI:    pairingURI,
		WalletPubkey:  wire.WalletPubkey,
		ExpiresAt:     wire.ExpiresAt,
		FeesPpm:       wire.FeesPpm,
		BudgetRenewal: wire.BudgetRenewal,
	}, nil
}

// decryptFromPubkey decrypts a NIP-44 payload keyed to privKeyHex and
// pubKeyHex — the same derivation nip47's own encrypted-response handling
// uses (schnorr.ParsePubKey for the 32-byte x-only nostr pubkey,
// nip44.GenerateConversationKey, nip44.Decrypt). Mirrors nipcash's own
// unexported helper of the same name — small enough (and specific enough to
// each package's own error-wrapping conventions) that a shared package
// isn't worth the indirection.
func decryptFromPubkey(privKeyHex, pubKeyHex, ciphertext string) (string, error) {
	privBytes, err := hex.DecodeString(privKeyHex)
	if err != nil {
		return "", fmt.Errorf("nipcw: invalid private key: %w", err)
	}
	priv, _ := btcec.PrivKeyFromBytes(privBytes)
	pubBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return "", fmt.Errorf("nipcw: invalid public key: %w", err)
	}
	pub, err := schnorr.ParsePubKey(pubBytes)
	if err != nil {
		return "", fmt.Errorf("nipcw: invalid public key: %w", err)
	}
	key, err := nip44.GenerateConversationKey(priv, pub)
	if err != nil {
		return "", fmt.Errorf("nipcw: derive decryption key: %w", err)
	}
	return nip44.Decrypt(ciphertext, key)
}
