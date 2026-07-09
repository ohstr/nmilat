package utils

import (
	"testing"

	"github.com/flokiorg/go-flokicoin/chainutil/bech32"
	"github.com/stretchr/testify/assert"
)

func TestValidateLNURL(t *testing.T) {
	// Helper to encode a string as LNURL bech32
	encodeLNURL := func(urlStr string) string {
		bits5, err := bech32.ConvertBits([]byte(urlStr), 8, 5, true)
		if err != nil {
			panic(err)
		}
		encoded, err := bech32.Encode("lnurl", bits5)
		if err != nil {
			panic(err)
		}
		return encoded
	}

	tests := []struct {
		name    string
		lnurl   string
		wantErr bool
	}{
		{
			name:    "Valid Standard LNURL",
			lnurl:   encodeLNURL("https://service.com/api?q=abc"),
			wantErr: false,
		},
		{
			name:    "Valid Onion LNURL",
			lnurl:   encodeLNURL("http://v2onion.onion/api?q=abc"),
			wantErr: false,
		},
		{
			name:    "Invalid Bech32",
			lnurl:   "lnurl1invalidbech32",
			wantErr: true,
		},
		{
			name: "Wrong Prefix",
			lnurl: func() string {
				bits5, _ := bech32.ConvertBits([]byte("https://service.com"), 8, 5, true)
				encoded, _ := bech32.Encode("npub", bits5)
				return encoded
			}(),
			wantErr: true,
		},
		{
			name:    "Invalid content (not a URL)",
			lnurl:   encodeLNURL("just some text, not a url"),
			wantErr: true,
		},
		{
			name:    "Insecure HTTP (non-onion)",
			lnurl:   encodeLNURL("http://service.com/api?q=abc"),
			wantErr: true,
		},
		{
			name:    "Invalid Scheme (ftp)",
			lnurl:   encodeLNURL("ftp://service.com/api?q=abc"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLNURL(tt.lnurl)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
