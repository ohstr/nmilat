package nip04

import (
	"testing"

	"github.com/ohstr/nmilat/utils"
)

type Account struct {
	privateKey, publicKey string
}

func NewAccount(t *testing.T, privKey string) Account {

	publicKey, err := utils.GetPublicKey(privKey)
	if err != nil {
		t.Fatal(err)
	}

	return Account{
		privateKey: privKey,
		publicKey:  publicKey,
	}
}

func TestNip04(t *testing.T) {

	accounts := map[string]Account{}
	accounts["sender"] = NewAccount(t, "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c")
	accounts["receiver"] = NewAccount(t, "127d42afe2be3f66d253823480a116f027132ff75f80a4d4ecc3bbbe8bb90226")

	t.Run("check", func(t *testing.T) {

		message := "hellostr"
		ciphertext, err := Encrypt(message, accounts["sender"].privateKey, accounts["receiver"].publicKey)
		if err != nil {
			t.Fatal(err)
		}

		t.Logf("ciphertext=%s", ciphertext)

		plaintext, err := Decrypt(ciphertext, accounts["sender"].publicKey, accounts["receiver"].privateKey)
		if err != nil {
			t.Fatal(err)
		}

		if plaintext != message {
			t.Fatalf("mismatched data %s <> %s", plaintext, message)
		}
	})

	t.Run("double_check", func(t *testing.T) {

		message := "hellostr"
		ciphertext := "kaj6i6qoZibMeT//h1DxnA==?iv=6cocv8uk69EfxwQ4FKjV2w=="

		plaintext, err := Decrypt(ciphertext, accounts["sender"].publicKey, accounts["receiver"].privateKey)
		if err != nil {
			t.Fatal(err)
		}

		if message != plaintext {
			t.Fatalf("mismatched data %s <> %s", message, plaintext)
		}
	})

}
