package nipOA

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
	"github.com/ohstr/nmilat/nip19"
	"github.com/ohstr/nmilat/utils"
)

// MethodSignAttestation is the NIP-46/NIP-LS method a remote signer answers
// with an attestation signature: params [subordinate pubkey hex, conditions],
// result the 64-byte BIP-340 signature as hex. It is not one of NIP-46's
// built-in methods: a signer offers it as a custom method (nipLS's
// ServerConfig.Methods, AttestationMethod there) and gates it itself.
const MethodSignAttestation = "nipoa_attest"

var (
	// ErrInvalidSubordinatePubkey is a subordinate key that is not 32-byte hex.
	ErrInvalidSubordinatePubkey = errors.New("nipoa: invalid subordinate pubkey")
	// ErrNoSigner is a nil Signer passed to Sign.
	ErrNoSigner = errors.New("nipoa: no signer")
)

// Signer signs attestations: a BIP-340 signature over
// SHA256(Preimage(subordinate, conditions)) by the attester's key. A key in
// this process (KeySigner) and a remote signer reached by a NIP-46 or NIP-LS
// call (RemoteSigner) both implement it.
type Signer interface {
	// PubKey is the attester's pubkey, lowercase hex.
	PubKey() string
	// SignAttestation returns the signature as hex. Callers go through Sign,
	// which checks its inputs first and the signature after.
	SignAttestation(ctx context.Context, subordinatePubkey, conditions string) (string, error)
}

// Sign has signer attest subordinateHex under conditions and returns the
// auth tag ["auth", attester, conditions, sig]. conditions must parse
// (ParseConditions) and is signed verbatim; the attester may not attest
// itself. The signature is verified before it is returned, so a remote
// signer's wrong answer never leaves here as a tag.
func Sign(ctx context.Context, signer Signer, subordinateHex, conditions string) ([]string, error) {
	if signer == nil {
		return nil, ErrNoSigner
	}
	if err := utils.Validate32Key(subordinateHex); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidSubordinatePubkey, err)
	}
	attester := signer.PubKey()
	if err := utils.Validate32Key(attester); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidOwnerPubkey, err)
	}
	if attester == subordinateHex {
		return nil, ErrSelfAttestation
	}
	if _, err := ParseConditions(conditions); err != nil {
		return nil, err
	}
	sig, err := signer.SignAttestation(ctx, subordinateHex, conditions)
	if err != nil {
		return nil, fmt.Errorf("nipoa: sign: %w", err)
	}
	sig = strings.ToLower(strings.TrimSpace(sig))
	if err := VerifySignature(attester, subordinateHex, conditions, sig); err != nil {
		return nil, err
	}
	return []string{TagName, attester, conditions, sig}, nil
}

// Until is the conditions clause bounding an attestation to times before t:
// "created_at<unix(t)". Past it, EvaluateTimeClauses fails for every later
// time, which is how a holder of the attestation reads it as expired.
func Until(t time.Time) string {
	return "created_at<" + strconv.FormatInt(t.Unix(), 10)
}

// ExpiredAt reports whether the conditions no longer hold at now: a
// created_at< bound reached, or a created_at> bound not yet passed.
func (c Conditions) ExpiredAt(now time.Time) bool {
	u := now.Unix()
	if u < 0 {
		u = 0
	}
	return !c.EvaluateTimeClauses(uint64(u))
}

// KeySigner signs attestations with a private key held in this process.
type KeySigner struct {
	priv, pub string
}

// NewKeySigner wraps a private key given as hex or nsec.
func NewKeySigner(privKey string) (*KeySigner, error) {
	priv := strings.TrimSpace(privKey)
	if strings.HasPrefix(priv, "nsec1") {
		h, err := nip19.DecodePrivateKey(priv)
		if err != nil {
			return nil, fmt.Errorf("nipoa: invalid nsec: %w", err)
		}
		priv = h
	}
	priv = strings.ToLower(priv)
	pub, err := utils.GetPublicKey(priv)
	if err != nil {
		return nil, fmt.Errorf("nipoa: invalid private key: %w", err)
	}
	return &KeySigner{priv: priv, pub: pub}, nil
}

// PubKey is the key's pubkey, lowercase hex.
func (k *KeySigner) PubKey() string { return k.pub }

// SignAttestation signs SHA256(Preimage(subordinatePubkey, conditions)).
func (k *KeySigner) SignAttestation(_ context.Context, subordinatePubkey, conditions string) (string, error) {
	privKey, err := utils.ParsePrivateKeyHex(k.priv)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}
	digest := sha256.Sum256(Preimage(subordinatePubkey, conditions))
	sig, err := schnorr.Sign(privKey, digest[:])
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(sig.Serialize()), nil
}

// Caller makes one NIP-46 method call. nipLS's *Client implements it.
type Caller interface {
	Call(ctx context.Context, method string, params ...string) (string, error)
}

// RemoteSigner signs attestations through a remote signer's
// MethodSignAttestation, the key never leaving it.
type RemoteSigner struct {
	caller Caller
	pub    string
}

// NewRemoteSigner makes a RemoteSigner for the signer reached by caller,
// whose key is pubkey (lowercase hex; nipLS's Client.PubKey gives it).
func NewRemoteSigner(caller Caller, pubkey string) (*RemoteSigner, error) {
	if caller == nil {
		return nil, ErrNoSigner
	}
	if err := utils.Validate32Key(pubkey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidOwnerPubkey, err)
	}
	return &RemoteSigner{caller: caller, pub: pubkey}, nil
}

// PubKey is the remote key's pubkey, lowercase hex.
func (r *RemoteSigner) PubKey() string { return r.pub }

// SignAttestation calls MethodSignAttestation.
func (r *RemoteSigner) SignAttestation(ctx context.Context, subordinatePubkey, conditions string) (string, error) {
	return r.caller.Call(ctx, MethodSignAttestation, subordinatePubkey, conditions)
}
