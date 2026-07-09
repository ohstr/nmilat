package nip49

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNIP49_EndToEnd(t *testing.T) {
	// 32-byte private key
	privKey := "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f"
	password := "correct horse battery staple"

	// Encrypt
	encoded, err := Encrypt(privKey, password)
	require.NoError(t, err)
	assert.Contains(t, encoded, "ncryptsec1")
	t.Logf("Encrypted: %s", encoded)

	// Decrypt
	decrypted, err := Decrypt(encoded, password)
	require.NoError(t, err)
	assert.Equal(t, privKey, decrypted)

	// Bad Password
	_, err = Decrypt(encoded, "wrong")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decryption failed")
}
