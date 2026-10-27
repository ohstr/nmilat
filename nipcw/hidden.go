package nipcw

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/ohstr/nmilat/nip44"
)

// EncryptHiddenMember is a hidden_p value (NIP-CW §Hidden Members): the member's
// pubkey as 64 lowercase hex, NIP-44 v2 encrypted under the conversation key
// between the provider and the Hub's inbox pubkey (its kind-11190 inbox tag),
// never its connection pubkey. Each call gives a fresh payload.
func EncryptHiddenMember(providerPriv, inboxPub, memberPub string) (string, error) {
	if !isLowerHex64(memberPub) {
		return "", fmt.Errorf("nipcw: a hidden member is 64 lowercase hex")
	}
	key, err := conversationKey(providerPriv, inboxPub)
	if err != nil {
		return "", err
	}
	return nip44.Encrypt(memberPub, key)
}

// DecryptHiddenMember reads a hidden_p value with the Hub's inbox key and the
// provider pubkey. A payload that does not decrypt, or decrypts to anything but
// 64 lowercase hex, is an error; a Hub skips such an entry.
func DecryptHiddenMember(inboxPriv, providerPub, payload string) (string, error) {
	key, err := conversationKey(inboxPriv, providerPub)
	if err != nil {
		return "", err
	}
	plain, err := nip44.Decrypt(payload, key)
	if err != nil {
		return "", fmt.Errorf("nipcw: hidden_p does not decrypt: %w", err)
	}
	if !isLowerHex64(plain) {
		return "", fmt.Errorf("nipcw: hidden_p is not a 64 lowercase hex pubkey")
	}
	return plain, nil
}

// SealHiddenMembers builds the hidden_p tags for a publish of the set: one entry
// per member per inbox key, every one encrypted afresh, in an order shuffled with
// rnd (crypto/rand when nil), as a provider SHOULD on each publish.
func SealHiddenMembers(providerPriv string, inboxPubs, members []string, rnd io.Reader) ([][]string, error) {
	if rnd == nil {
		rnd = rand.Reader
	}
	tags := make([][]string, 0, len(inboxPubs)*len(members))
	for _, inbox := range inboxPubs {
		for _, m := range members {
			payload, err := EncryptHiddenMember(providerPriv, inbox, m)
			if err != nil {
				return nil, err
			}
			tags = append(tags, []string{"hidden_p", payload})
		}
	}
	for i := len(tags) - 1; i > 0; i-- {
		var b [8]byte
		if _, err := io.ReadFull(rnd, b[:]); err != nil {
			return nil, fmt.Errorf("nipcw: shuffle: %w", err)
		}
		j := int(binary.BigEndian.Uint64(b[:]) % uint64(i+1))
		tags[i], tags[j] = tags[j], tags[i]
	}
	return tags, nil
}
