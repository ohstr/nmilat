// Package config holds the embedded YAML configuration for the search
// subsystem: profile scoring weights, NIP-05/LUD-16 verification bonuses,
// and search-engine/cache tuning. It has no NIP of its own.
package config

import (
	_ "embed"
	"sync"

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
	Cache        CacheConfig        `yaml:"cache"`
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
	Nip05Score             int64 `yaml:"nip05_score"`
	Lud16Score             int64 `yaml:"lud16_score"`
	Lud16ChainLimit        int64 `yaml:"lud16_chain_limit"`
	DefaultPredefinedBonus int64 `yaml:"default_predefined_bonus"`
}

// EngineConfig holds search engine tuning settings.
type EngineConfig struct {
	MaxTotalHits       int `yaml:"max_total_hits"`
	TypoOneMinWordSize int `yaml:"typo_one_min_word_size"`
	TypoTwoMinWordSize int `yaml:"typo_two_min_word_size"`
	AboutMaxLength     int `yaml:"about_max_length"`
}

// CacheConfig holds cache-related settings.
type CacheConfig struct {
	VerificationTTLHours int `yaml:"verification_ttl_hours"`
}

var (
	instance *AppConfig
	once     sync.Once
)

// Get returns the singleton AppConfig, parsed once from the embedded config.yaml.
func Get() *AppConfig {
	once.Do(func() {
		instance = &AppConfig{}
		if err := yaml.Unmarshal(configData, instance); err != nil {
			panic("failed to parse embedded config.yaml: " + err.Error())
		}
	})
	return instance
}
