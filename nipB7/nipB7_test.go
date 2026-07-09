package nipB7

import (
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

const testPrivKey = "48939ec93986b59b58d7206887b42ff74d99dd3258782e2fdfd720eb74d547a5"

func signed(t *testing.T, ev *nip01.Event) *nip01.Event {
	t.Helper()
	if err := ev.Sign(testPrivKey); err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	return ev
}

func TestNewBlossomServerListAndParse(t *testing.T) {
	servers := []string{"https://blossom1.example", "https://blossom2.example"}
	ev, err := NewBlossomServerList("", servers)
	if err != nil {
		t.Fatalf("NewBlossomServerList() error = %v", err)
	}
	ev = signed(t, ev)

	sl, err := ParseBlossomServerList(ev)
	if err != nil {
		t.Fatalf("ParseBlossomServerList() error = %v", err)
	}
	if len(sl.Servers) != 2 {
		t.Fatalf("Servers = %v", sl.Servers)
	}

	if err := ValidateBlossomServerList(ev); err != nil {
		t.Errorf("ValidateBlossomServerList() error = %v", err)
	}
}

func TestNewBlossomServerListErrors(t *testing.T) {
	if _, err := NewBlossomServerList("", nil); err == nil {
		t.Error("expected error for empty server list")
	}
	if _, err := NewBlossomServerList("", []string{"not-a-url"}); err == nil {
		t.Error("expected error for invalid server url")
	}
	if _, err := NewBlossomServerList("", []string{"wss://relay.example"}); err == nil {
		t.Error("expected error for non-http(s) scheme")
	}
}

func TestParseBlossomServerListErrors(t *testing.T) {
	tests := []struct {
		name string
		kind int
		tags [][]string
	}{
		{name: "wrong kind", kind: 1, tags: nil},
		{name: "bad server url", kind: KindBlossomServerList, tags: [][]string{{"server", "not-a-url"}}},
		{name: "bad server scheme", kind: KindBlossomServerList, tags: [][]string{{"server", "wss://relay.example"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := &nip01.Event{Kind: tt.kind, Tags: tt.tags}
			if _, err := ParseBlossomServerList(ev); err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

const testHash = "acf592919bf86796c662468ff68c0fdf45780ca022b422157f5493bc6a51fb93"

func TestExtractHashFromURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantOK  bool
		wantExt string
	}{
		{name: "with extension", url: "https://cdn.example/" + testHash + ".png", wantOK: true, wantExt: "png"},
		{name: "without extension", url: "https://cdn.example/" + testHash, wantOK: true, wantExt: ""},
		{name: "not a hash", url: "https://cdn.example/random-file.png", wantOK: false},
		{name: "invalid url", url: "://bad", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, ext, ok := ExtractHashFromURL(tt.url)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if hash != testHash {
				t.Errorf("hash = %q, want %q", hash, testHash)
			}
			if ext != tt.wantExt {
				t.Errorf("ext = %q, want %q", ext, tt.wantExt)
			}
		})
	}
}

func TestBuildServerURL(t *testing.T) {
	got, err := BuildServerURL("https://cdn.example/", testHash, "png")
	if err != nil {
		t.Fatalf("BuildServerURL() error = %v", err)
	}
	want := "https://cdn.example/" + testHash + ".png"
	if got != want {
		t.Errorf("BuildServerURL() = %q, want %q", got, want)
	}

	if _, err := BuildServerURL("https://cdn.example", "not-a-hash", ""); err == nil {
		t.Error("expected error for invalid hash")
	}
}
