package search

// ProfileDocument represents the structure stored in the search engine
type ProfileDocument struct {
	ID          string `json:"id"` // The Pubkey (Primary Key)
	Npub        string `json:"npub"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	About       string `json:"about"` // Truncated to max length
	Nip05       string `json:"nip05"`
	Lud16       string `json:"lud16"`
	Picture     string `json:"picture"`
	Score       int64  `json:"score"`      // Unified total score (Base + Verify)
	IndexedAt   int64  `json:"indexed_at"` // Unix timestamp
}
