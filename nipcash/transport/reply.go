package transport

import (
	"fmt"

	btcec "github.com/flokiorg/go-flokicoin/crypto"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip44"
	"github.com/ohstr/nmilat/nip59"
)

// WrapResponseChunk builds one kind-23191 reply chunk (NIP-CASH §The Reply Key):
// signed by a fresh key used once, created_at randomised into the past, tagged
// only ["p", reply_to], content the NIP-44 v2 encryption of plaintext with
// replyKey as the conversation key, no ECDH.
func WrapResponseChunk(plaintext []byte, replyKey [32]byte, replyTo string) (*nip01.Event, error) {
	if len(replyTo) != keyHexLen || !isLowerHex(replyTo) {
		return nil, fmt.Errorf("%w: reply_to must be %d lowercase hex characters", ErrEnvelopeMalformed, keyHexLen)
	}
	sealed, err := nip44.Encrypt(string(plaintext), replyKey[:])
	if err != nil {
		return nil, fmt.Errorf("transport: encrypt reply chunk: %w", err)
	}
	key, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, fmt.Errorf("transport: chunk key: %w", err)
	}
	ev := nip01.NewEvent(KindPrivateResponse, sealed)
	ev.Tags = [][]string{{"p", replyTo}}
	ev.CreatedAt = nip59.RandomizedCreatedAt()
	if err := ev.Sign(fmt.Sprintf("%x", key.Serialize())); err != nil {
		return nil, fmt.Errorf("transport: sign reply chunk: %w", err)
	}
	return ev, nil
}
