package search

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/search/ranking"
	"github.com/stretchr/testify/assert"
)

func TestFromEvent(t *testing.T) {
	tests := []struct {
		name          string
		event         *nip01.Event
		wantNil       bool
		wantScore     int64
		wantName      string
		wantAboutLen  int
		expectedError bool
	}{
		{
			name: "Ignored Kind",
			event: &nip01.Event{
				Kind: 1,
			},
			wantNil: true,
		},
		{
			name: "Valid Profile",
			event: &nip01.Event{
				Kind:      0,
				PubKey:    "pubkey1",
				CreatedAt: uint64(time.Now().Unix()),
				Content:   `{"name": "alice", "about": "bio", "picture": "https://example.com/pic.jpg"}`,
			},
			wantScore: 40, // 10 (Base) + 0 (About short) + 30 (Picture http) = 40.
			// Logic: Base (+10). About "bio" (len 3) < 15 (+0). Picture "https..." (+30). Total 40.
			// Let's re-read logic:
			// Base: name != "" -> +10.
			// About: len > 15 -> +10. (Here len=3 -> +0)
			// Picture: has http -> +30.
			// Total: 40.
			// Wait, previous test calculated 50 for "Complete Profile".
			// "I am a very interesting person with a long bio." is > 15.
			// "bio" is < 15.
			// So expected score is 40.
			wantName:     "alice",
			wantAboutLen: 3,
		},
		{
			name: "Invalid JSON Content",
			event: &nip01.Event{
				Kind:    0,
				PubKey:  "pubkey2",
				Content: `INVALID_JSON`,
			},
			wantScore: -500, // Penalty for invalid content (or similar fallthrough)
		},
		{
			name: "Truncate Long About",
			event: &nip01.Event{
				Kind:   0,
				PubKey: "pubkey3",
				Content: func() string {
					longAbout := strings.Repeat("a", 2000)
					c := MetadataContent{Name: "bob", About: longAbout}
					b, _ := json.Marshal(c)
					return string(b)
				}(),
			},
			wantName:     "bob",
			wantAboutLen: 1024,
			wantScore:    20, // Base (+10), About > 15 (+10), Picture "" (+0). Total 20.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := FromEvent(tt.event)
			if tt.wantNil {
				assert.Nil(t, doc)
				return
			}
			assert.NotNil(t, doc)
			assert.Equal(t, tt.wantScore, doc.Score, "Score mismatch")

			if tt.wantName != "" {
				assert.Equal(t, tt.wantName, doc.Name)
			}
			if tt.wantAboutLen > 0 {
				assert.Equal(t, tt.wantAboutLen, len(doc.About))
			}
		})
	}
}

// Re-verify score calculation used in table
func TestScoreConsistency(t *testing.T) {
	// "Valid Profile" case
	// name="alice" (+10)
	// about="bio" (+0)
	// picture="https://..." (+30)
	// Total = 40.
	s := ranking.CalculateScore("alice", "", "bio", "", "", "https://example.com")
	assert.Equal(t, int64(40), s)
}
