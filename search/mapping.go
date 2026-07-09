package search

import (
	"encoding/json"
	"time"

	"github.com/ohstr/nmilat/config"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip19"
	"github.com/ohstr/nmilat/search/ranking"
)

type MetadataContent struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	About       string `json:"about"`
	Nip05       string `json:"nip05"`
	Lud16       string `json:"lud16"`
	Picture     string `json:"picture"`
}

// FromEvent converts a Nostr Event (Kind 0) into a Search Document.
func FromEvent(ev *nip01.Event) *ProfileDocument {
	if ev.Kind != 0 {
		return nil
	}

	var content MetadataContent
	if err := json.Unmarshal([]byte(ev.Content), &content); err != nil {
		// If content is invalid JSON, we still index the pubkey but with empty metadata
		// to allow minimal discoverability if desired, or we could skip.
		// For now, let's return a basic doc.
		return &ProfileDocument{
			ID:        ev.PubKey,
			IndexedAt: time.Now().Unix(),
			Score:     -500, // Penalize bad content
		}
	}

	// Truncate 'About' to avoid massive payload
	about := content.About
	maxAbout := config.Get().Search.Engine.AboutMaxLength
	if len(about) > maxAbout {
		about = about[:maxAbout]
	}

	// Calculate Score
	score := ranking.CalculateScore(
		content.Name,
		content.DisplayName,
		about,
		content.Nip05,
		content.Lud16,
		content.Picture,
	)

	npub, _ := nip19.EncodePublicKey(ev.PubKey)

	return &ProfileDocument{
		ID:          ev.PubKey,
		Npub:        npub,
		Name:        content.Name,
		DisplayName: content.DisplayName,
		About:       about,
		Nip05:       content.Nip05,
		Lud16:       content.Lud16,
		Picture:     content.Picture,
		Score:       score,
		IndexedAt:   time.Now().Unix(),
	}
}
