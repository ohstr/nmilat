package nip11

import (
	"encoding/json"
	"strings"
	"testing"
)

// The NIP-11 "icon" field is served when set and left out when empty.
func TestMetadataIcon(t *testing.T) {
	b, err := json.Marshal(Metadata{Name: "r", Icon: "https://relay.example/icon.png"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"icon":"https://relay.example/icon.png"`) {
		t.Fatalf("icon missing: %s", b)
	}
	b, _ = json.Marshal(Metadata{Name: "r"})
	if strings.Contains(string(b), `"icon"`) {
		t.Fatalf("empty icon serialized: %s", b)
	}
}

// The NIP-11 "banner" field is served when set and left out when empty.
func TestMetadataBanner(t *testing.T) {
	b, err := json.Marshal(Metadata{Name: "r", Banner: "https://relay.example/banner.png"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"banner":"https://relay.example/banner.png"`) {
		t.Fatalf("banner missing: %s", b)
	}
	b, _ = json.Marshal(Metadata{Name: "r"})
	if strings.Contains(string(b), `"banner"`) {
		t.Fatalf("empty banner serialized: %s", b)
	}
}
