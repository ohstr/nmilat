package nipB7

import (
	"errors"
	"testing"
)

func TestParseURIRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		uri  URI
	}{
		{name: "bare", uri: URI{Hash: testHash, Ext: "png"}},
		{name: "no ext defaults to bin", uri: URI{Hash: testHash}},
		{name: "with authors", uri: URI{Hash: testHash, Ext: "png", Authors: []string{"pub1", "pub2"}}},
		{name: "with servers", uri: URI{Hash: testHash, Ext: "png", Servers: []string{"https://a.example", "https://b.example"}}},
		{name: "with size", uri: URI{Hash: testHash, Ext: "png", Size: 12345}},
		{name: "everything", uri: URI{
			Hash: testHash, Ext: "pdf",
			Authors: []string{"pub1"}, Servers: []string{"https://a.example"}, Size: 42,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := tt.uri.String()
			got, err := ParseURI(raw)
			if err != nil {
				t.Fatalf("ParseURI(%q) error = %v", raw, err)
			}
			if got.Hash != tt.uri.Hash {
				t.Errorf("Hash = %q, want %q", got.Hash, tt.uri.Hash)
			}
			wantExt := tt.uri.Ext
			if wantExt == "" {
				wantExt = defaultURIExt
			}
			if got.Ext != wantExt {
				t.Errorf("Ext = %q, want %q", got.Ext, wantExt)
			}
			if len(got.Authors) != len(tt.uri.Authors) {
				t.Errorf("Authors = %v, want %v", got.Authors, tt.uri.Authors)
			}
			if len(got.Servers) != len(tt.uri.Servers) {
				t.Errorf("Servers = %v, want %v", got.Servers, tt.uri.Servers)
			}
			if got.Size != tt.uri.Size {
				t.Errorf("Size = %d, want %d", got.Size, tt.uri.Size)
			}
		})
	}
}

func TestParseURIErrors(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr error
	}{
		{name: "missing scheme", raw: testHash + ".png", wantErr: ErrInvalidURIScheme},
		{name: "wrong scheme", raw: "https://" + testHash + ".png", wantErr: ErrInvalidURIScheme},
		{name: "bad hash", raw: "blossom:not-a-hash.png", wantErr: ErrInvalidURIHash},
		{name: "bad sz", raw: "blossom:" + testHash + ".png?sz=not-a-number", wantErr: ErrInvalidURISize},
		{name: "negative sz", raw: "blossom:" + testHash + ".png?sz=-5", wantErr: ErrInvalidURISize},
		{name: "malformed query escape", raw: "blossom:" + testHash + ".png?%zz", wantErr: ErrInvalidURIScheme},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseURI(tt.raw)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestURIStringDefaultExt(t *testing.T) {
	u := URI{Hash: testHash}
	want := "blossom:" + testHash + ".bin"
	if got := u.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}
