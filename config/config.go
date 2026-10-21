// Package config holds the embedded YAML configuration for the search
// subsystem: profile scoring weights, NIP-05/LUD-16 verification bonuses,
// and search-engine/cache tuning. It has no NIP of its own.
package config

import (
	_ "embed"
	"sync"
	"sync/atomic"

	"gopkg.in/yaml.v3"
)

//go:embed config.yaml
var configData []byte

// AppConfig is the top-level configuration structure.
type AppConfig struct {
	Search SearchConfig `yaml:"search"`
}

// SearchConfig groups all search-related configuration.
type SearchConfig struct {
	Scoring      ScoringConfig      `yaml:"scoring"`
	Verification VerificationConfig `yaml:"verification"`
	Engine       EngineConfig       `yaml:"engine"`
	Social       SocialConfig       `yaml:"social"`
}

// SocialConfig weighs followers and received zaps into a profile's score.
// Zaps count by sender: each sender adds at most PerSenderCap sats,
// scaled by how established the sender's own profile is.
type SocialConfig struct {
	FollowersWeight float64 `yaml:"followers_weight"`
	FollowersCap    float64 `yaml:"followers_cap"`
	ZapsWeight      float64 `yaml:"zaps_weight"`
	ZappersWeight   float64 `yaml:"zappers_weight"`
	ZapsCap         float64 `yaml:"zaps_cap"`
	// PerSenderCap is in sats (units, not milli-units).
	PerSenderCap uint64 `yaml:"per_sender_cap"`
	// TrustedSenderScore is the base+check score at which a sender counts
	// fully; below it the sender counts proportionally, never less than
	// MinSenderFactor.
	TrustedSenderScore float64 `yaml:"trusted_sender_score"`
	MinSenderFactor    float64 `yaml:"min_sender_factor"`
}

// ScoringConfig holds profile scoring values.
type ScoringConfig struct {
	IdentityBase     int64 `yaml:"identity_base"`
	AboutBonus       int64 `yaml:"about_bonus"`
	PictureBonus     int64 `yaml:"picture_bonus"`
	HexNamePenalty   int64 `yaml:"hex_name_penalty"`
	GibberishPenalty int64 `yaml:"gibberish_penalty"`
	GhostPenalty     int64 `yaml:"ghost_penalty"`
	MinAboutLength   int   `yaml:"min_about_length"`
	MinGibberishLen  int   `yaml:"min_gibberish_length"`
}

// VerificationConfig holds verification scoring values.
type VerificationConfig struct {
	Nip05Score      int64 `yaml:"nip05_score"`
	Lud16Score      int64 `yaml:"lud16_score"`
	Lud16ChainLimit int64 `yaml:"lud16_chain_limit"`
}

// EngineConfig holds search engine tuning settings.
type EngineConfig struct {
	MaxTotalHits       int `yaml:"max_total_hits"`
	TypoOneMinWordSize int `yaml:"typo_one_min_word_size"`
	TypoTwoMinWordSize int `yaml:"typo_two_min_word_size"`
	AboutMaxLength     int `yaml:"about_max_length"`
}

var (
	instance atomic.Pointer[AppConfig]
	once     sync.Once
)

// Get returns the AppConfig: the embedded config.yaml plus any Configure
// overrides. Treat it as read-only.
func Get() *AppConfig {
	once.Do(func() {
		cfg := &AppConfig{}
		if err := yaml.Unmarshal(configData, cfg); err != nil {
			panic("failed to parse embedded config.yaml: " + err.Error())
		}
		instance.Store(cfg)
	})
	return instance.Load()
}

// Configure replaces the config with a copy changed by fn, e.g. to apply
// an embedder's scoring weights at startup.
func Configure(fn func(*AppConfig)) {
	next := *Get()
	fn(&next)
	instance.Store(&next)
}
