package nip59

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/flokiorg/go-flokicoin/crypto/schnorr"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/utils"
)

// EncryptionNIP44V2 is the scheme name a Sealer and an Opener are called
// with; it matches nip46.EncryptionNIP44V2.
const EncryptionNIP44V2 = "nip44_v2"

// Sealer is the sender's key: it signs the seal and encrypts the rumor.
// nip46.LocalKey and nipLS.Client implement it, so the key can stay in a
// signer.
type Sealer interface {
	PubKey() string
	Sign(ctx context.Context, ev *nip01.Event) error
	Encrypt(ctx context.Context, scheme, peerPubKey, plaintext string) (string, error)
}

// Opener is the recipient's key: it decrypts the wrap and the seal.
type Opener interface {
	PubKey() string
	Decrypt(ctx context.Context, scheme, peerPubKey, ciphertext string) (string, error)
}

// ErrForeignSender is Unwrap refusing a seal whose author is not in
// OpenOptions.From. The seal was not decrypted.
var ErrForeignSender = errors.New("nip59: seal is from a sender not asked for")

// PrepareRumor makes ev a rumor by author: an unsigned event with its
// pubkey and id set.
func PrepareRumor(ev *nip01.Event, authorPubKey string) error {
	ev.PubKey, ev.Sig = strings.ToLower(authorPubKey), ""
	if ev.Tags == nil {
		ev.Tags = [][]string{}
	}
	id, err := ev.HashID()
	if err != nil {
		return fmt.Errorf("nip59: hash rumor: %w", err)
	}
	ev.ID = hex.EncodeToString(id)
	return nil
}

// rumorJSON is a rumor on the wire: an event without "sig".
type rumorJSON struct {
	ID        string     `json:"id"`
	PubKey    string     `json:"pubkey"`
	CreatedAt uint64     `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
}

// Seal makes rumor a rumor by sender and seals it to recipientPubKey: a
// kind 13 whose content is the rumor, NIP-44 encrypted, signed by sender.
func Seal(ctx context.Context, sender Sealer, rumor *nip01.Event, recipientPubKey string) (*nip01.Event, error) {
	if err := checkPubKey(recipientPubKey); err != nil {
		return nil, err
	}
	if err := PrepareRumor(rumor, sender.PubKey()); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(rumorJSON{rumor.ID, rumor.PubKey, rumor.CreatedAt, rumor.Kind, rumor.Tags, rumor.Content})
	if err != nil {
		return nil, fmt.Errorf("nip59: marshal rumor: %w", err)
	}
	content, err := sender.Encrypt(ctx, EncryptionNIP44V2, strings.ToLower(recipientPubKey), string(raw))
	if err != nil {
		return nil, fmt.Errorf("nip59: encrypt seal: %w", err)
	}
	seal := nip01.NewEvent(KindSeal, content)
	seal.Tags = [][]string{}
	seal.PubKey = sender.PubKey()
	seal.CreatedAt = RandomizedCreatedAt()
	if err := sender.Sign(ctx, seal); err != nil {
		return nil, fmt.Errorf("nip59: sign seal: %w", err)
	}
	if !strings.EqualFold(seal.PubKey, rumor.PubKey) {
		return nil, errors.New("nip59: signer signed the seal as another pubkey")
	}
	return seal, nil
}

// WrapSeal gift-wraps seal to recipientPubKey under a one-time key.
func WrapSeal(seal *nip01.Event, recipientPubKey string) (*nip01.Event, error) {
	if err := checkPubKey(recipientPubKey); err != nil {
		return nil, err
	}
	recipientPub, err := parsePubKey(recipientPubKey)
	if err != nil {
		return nil, err
	}
	sealJSON, err := json.Marshal(seal)
	if err != nil {
		return nil, fmt.Errorf("nip59: marshal seal: %w", err)
	}
	ephemeralPriv, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("nip59: ephemeral key: %w", err)
	}
	wrapKey, err := nip44.GenerateConversationKey(ephemeralPriv, recipientPub)
	if err != nil {
		return nil, fmt.Errorf("nip59: wrap conversation key: %w", err)
	}
	content, err := nip44.Encrypt(string(sealJSON), wrapKey)
	if err != nil {
		return nil, fmt.Errorf("nip59: encrypt wrap: %w", err)
	}
	wrap := nip01.NewEvent(KindGiftWrap, content)
	wrap.Tags = [][]string{{"p", strings.ToLower(recipientPubKey)}}
	wrap.CreatedAt = RandomizedCreatedAt()
	if err := wrap.Sign(hex.EncodeToString(ephemeralPriv.Serialize())); err != nil {
		return nil, fmt.Errorf("nip59: sign wrap: %w", err)
	}
	return wrap, nil
}

// OpenOptions configures Unwrap.
type OpenOptions struct {
	// From, when set, lists the hex pubkeys whose seals may be opened. A
	// seal from anyone else is returned undecrypted with ErrForeignSender.
	From []string
}

// Opened is an unwrapped gift wrap.
type Opened struct {
	Wrap  *nip01.Event // nil when a bare seal was opened
	Seal  *nip01.Event
	Rumor *nip01.Event // nil with ErrForeignSender
	// Sender is the seal's author, checked: the seal's signature verifies and
	// the rumor claims the same pubkey.
	Sender string
}

// Unwrap opens a kind 1059 gift wrap, or a bare kind 13 seal, addressed to
// recipient. It checks the wrap's and the seal's signatures, the rumor's id,
// and that the rumor's author is the seal's.
func Unwrap(ctx context.Context, recipient Opener, ev *nip01.Event, opts OpenOptions) (*Opened, error) {
	out := &Opened{}
	seal := ev
	switch ev.Kind {
	case KindGiftWrap:
		if err := ev.Verify(nip01.WithoutPowCheck()); err != nil {
			return nil, fmt.Errorf("nip59: gift wrap does not verify: %w", err)
		}
		inner, err := recipient.Decrypt(ctx, EncryptionNIP44V2, ev.PubKey, ev.Content)
		if err != nil {
			return nil, fmt.Errorf("nip59: open gift wrap: %w", err)
		}
		if seal, err = decodeEvent(inner); err != nil {
			return nil, fmt.Errorf("nip59: gift wrap: %w", err)
		}
		if seal.Kind != KindSeal {
			return nil, fmt.Errorf("nip59: gift wrap holds kind %d, not a seal", seal.Kind)
		}
		out.Wrap = ev
	case KindSeal:
	default:
		return nil, fmt.Errorf("nip59: kind %d is not a gift wrap (1059) or seal (13)", ev.Kind)
	}
	if err := seal.Verify(nip01.WithoutPowCheck()); err != nil {
		return nil, fmt.Errorf("nip59: seal does not verify: %w", err)
	}
	out.Seal = seal
	if len(opts.From) > 0 && !containsFold(opts.From, seal.PubKey) {
		return out, ErrForeignSender
	}
	inner, err := recipient.Decrypt(ctx, EncryptionNIP44V2, seal.PubKey, seal.Content)
	if err != nil {
		return nil, fmt.Errorf("nip59: open seal: %w", err)
	}
	rumor, err := ParseRumor(inner, seal.PubKey)
	if err != nil {
		return nil, err
	}
	out.Rumor, out.Sender = rumor, strings.ToLower(seal.PubKey)
	return out, nil
}

// ParseRumor decodes a seal's plaintext and checks the rumor: its author is
// sealAuthor, and its id, when it has one, is its hash.
func ParseRumor(plaintext, sealAuthor string) (*nip01.Event, error) {
	rumor, err := decodeEvent(plaintext)
	if err != nil {
		return nil, fmt.Errorf("nip59: rumor: %w", err)
	}
	if err := CheckRumorID(rumor); err != nil {
		return nil, err
	}
	if !strings.EqualFold(rumor.PubKey, sealAuthor) {
		return nil, fmt.Errorf("nip59: rumor claims author %s but the seal is signed by %s", rumor.PubKey, sealAuthor)
	}
	return rumor, nil
}

// CheckRumorID refuses a rumor whose id is set but is not its hash. An empty
// id is allowed: some senders leave it out.
func CheckRumorID(rumor *nip01.Event) error {
	if rumor.ID == "" {
		return nil
	}
	id, err := rumor.HashID()
	if err != nil {
		return fmt.Errorf("nip59: rumor: %w", err)
	}
	if !strings.EqualFold(rumor.ID, hex.EncodeToString(id)) {
		return errors.New("nip59: rumor id does not match its content")
	}
	return nil
}

func decodeEvent(s string) (*nip01.Event, error) {
	var ev nip01.Event
	if err := json.Unmarshal([]byte(s), &ev); err != nil {
		return nil, fmt.Errorf("not a valid event: %w", err)
	}
	if ev.Tags == nil {
		ev.Tags = [][]string{}
	}
	return &ev, nil
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func checkPubKey(s string) error {
	if err := utils.Validate32Key(s); err != nil {
		return fmt.Errorf("nip59: invalid recipient public key: %w", err)
	}
	return nil
}

func parsePubKey(s string) (*btcec.PublicKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("nip59: invalid recipient public key: %w", err)
	}
	pub, err := schnorr.ParsePubKey(b)
	if err != nil {
		return nil, fmt.Errorf("nip59: invalid recipient public key: %w", err)
	}
	return pub, nil
}
