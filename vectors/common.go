package vectors

import (
	"crypto/sha256"
	"encoding/hex"
)

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// Withdraw KAT common inputs (K-WQ-1 … K-POCKET-6).
const (
	wdPriv1 = "0000000000000000000000000000000000000000000000000000000000000001"
	wdPriv3 = "0000000000000000000000000000000000000000000000000000000000000003"
	wdHub   = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" // key 1
	wdBill  = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5" // key 2
	wdSlice = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" // key 3
	wdCK1   = "22ced17fc7b3a6f7262d2dbe00b42d302948595468e025f4392b0a5022b8319d"
	kAddr1  = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
	kWQ1ID  = "bd16a92aef27ec468b00c715f9c3bf4f3cf4d148fa6cd62cbac0773c30f85a22"
)
