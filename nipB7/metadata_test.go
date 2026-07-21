package nipB7

import "testing"

func TestNIP94Tags(t *testing.T) {
	d := BlobDescriptor{
		URL:    "https://cdn.example/" + testHash + ".png",
		Sha256: testHash,
		Size:   1024,
		Type:   "image/png",
	}
	tags := NIP94Tags(d)

	want := map[string]string{
		"url":  d.URL,
		"x":    d.Sha256,
		"size": "1024",
		"m":    "image/png",
	}
	got := map[string]string{}
	for _, tag := range tags {
		if len(tag) >= 2 {
			got[tag[0]] = tag[1]
		}
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("tag %q = %q, want %q", k, got[k], v)
		}
	}
}

func TestNIP94TagsOmitsEmptyType(t *testing.T) {
	d := BlobDescriptor{URL: "https://cdn.example/x", Sha256: testHash, Size: 1}
	for _, tag := range NIP94Tags(d) {
		if tag[0] == "m" {
			t.Errorf("expected no m tag when Type is empty, got %v", tag)
		}
	}
}

func TestHashFromNIP94Tags(t *testing.T) {
	tags := [][]string{{"url", "https://cdn.example/x"}, {"x", testHash}, {"m", "image/png"}}
	hash, ok := HashFromNIP94Tags(tags)
	if !ok || hash != testHash {
		t.Errorf("HashFromNIP94Tags() = (%q, %v), want (%q, true)", hash, ok, testHash)
	}
}

func TestHashFromNIP94TagsNotFound(t *testing.T) {
	tags := [][]string{{"url", "https://cdn.example/x"}, {"x", "not-a-hash"}}
	if _, ok := HashFromNIP94Tags(tags); ok {
		t.Error("HashFromNIP94Tags() ok = true, want false")
	}
}
