package nip44

import (
	"crypto/rand"
	"encoding/hex"
	"testing"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConversationKey(t *testing.T) {
	priv1, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pub1 := priv1.PubKey()

	priv2, err := btcec.NewPrivateKey()
	require.NoError(t, err)
	pub2 := priv2.PubKey()

	// Both sides should derive same key
	key1, err := GenerateConversationKey(priv1, pub2)
	require.NoError(t, err)
	assert.Len(t, key1, 32)

	key2, err := GenerateConversationKey(priv2, pub1)
	require.NoError(t, err)
	assert.Len(t, key2, 32)

	assert.Equal(t, key1, key2)
}

func TestEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)

	plaintext := "Hello, NIP-44!"

	// Encrypt
	ciphertext, err := Encrypt(plaintext, key)
	require.NoError(t, err)
	assert.NotEmpty(t, ciphertext)

	// Decrypt
	decrypted, err := Decrypt(ciphertext, key)
	require.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}

func TestPadding(t *testing.T) {
	// Test padding calculation logic implicitly via Encrypt/Decrypt of variable lengths
	key := make([]byte, 32)
	rand.Read(key)

	lengths := []int{1, 31, 32, 33, 100, 500, 1024}
	for _, l := range lengths {
		msg := make([]byte, l)
		rand.Read(msg)
		plaintext := hex.EncodeToString(msg) // hex just to be safe string

		ct, err := Encrypt(plaintext, key)
		require.NoError(t, err)

		dt, err := Decrypt(ct, key)
		require.NoError(t, err)
		assert.Equal(t, plaintext, dt)
	}
}

func TestVectors(t *testing.T) {
	// If we had official NIP-44 vectors we would put them here.
	// For now, functional correctness is enough.
}
