package nip48

import (
	"testing"

	"github.com/ohstr/nmilat/nip01"
)

func mockEvent(tags [][]string) *nip01.Event {
	return &nip01.Event{Kind: 1, Content: "hello", Tags: tags}
}

func TestParseProxyTag(t *testing.T) {
	tests := []struct {
		name    string
		tags    [][]string
		want    *ProxyTag
		wantErr bool
	}{
		{
			name: "valid activitypub proxy tag",
			tags: [][]string{{TagNameProxy, "https://mastodon.example/users/alice/statuses/1", ProtocolActivityPub}},
			want: &ProxyTag{ID: "https://mastodon.example/users/alice/statuses/1", Protocol: ProtocolActivityPub},
		},
		{
			name:    "missing proxy tag",
			tags:    [][]string{{"e", "abc"}},
			wantErr: true,
		},
		{
			name:    "too few elements",
			tags:    [][]string{{TagNameProxy, "id-only"}},
			wantErr: true,
		},
		{
			name:    "duplicate proxy tags",
			tags:    [][]string{{TagNameProxy, "a", ProtocolRSS}, {TagNameProxy, "b", ProtocolWeb}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseProxyTag(mockEvent(tt.tags))
			if (err != nil) != tt.wantErr {
				t.Fatalf("ParseProxyTag() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.ID != tt.want.ID || got.Protocol != tt.want.Protocol {
				t.Errorf("ParseProxyTag() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestValidateProxyTag(t *testing.T) {
	if err := ValidateProxyTag(mockEvent(nil)); err != nil {
		t.Errorf("ValidateProxyTag() with no proxy tag should be valid, got %v", err)
	}

	valid := mockEvent([][]string{{TagNameProxy, "at://did:plc:abc/app.bsky.feed.post/xyz", ProtocolATProto}})
	if err := ValidateProxyTag(valid); err != nil {
		t.Errorf("ValidateProxyTag() valid tag returned error: %v", err)
	}

	invalid := mockEvent([][]string{{TagNameProxy, "id-only"}})
	if err := ValidateProxyTag(invalid); err == nil {
		t.Error("ValidateProxyTag() expected error for malformed tag")
	}
}

func TestAddProxyTag(t *testing.T) {
	ev := mockEvent(nil)
	AddProxyTag(ev, "https://example.com/post/1", ProtocolWeb)

	got, err := ParseProxyTag(ev)
	if err != nil {
		t.Fatalf("ParseProxyTag() after AddProxyTag() error = %v", err)
	}
	if got.ID != "https://example.com/post/1" || got.Protocol != ProtocolWeb {
		t.Errorf("AddProxyTag() produced %+v", got)
	}
}
