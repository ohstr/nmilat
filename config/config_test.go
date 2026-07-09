package config

import "testing"

func TestGet_ParsesEmbeddedConfig(t *testing.T) {
	cfg := Get()
	if cfg == nil {
		t.Fatal("expected a non-nil config")
	}

	if cfg.Search.Scoring.IdentityBase != 10 {
		t.Errorf("expected identity_base=10, got %d", cfg.Search.Scoring.IdentityBase)
	}
	if cfg.Search.Verification.Nip05Score != 50 {
		t.Errorf("expected nip05_score=50, got %d", cfg.Search.Verification.Nip05Score)
	}
	if cfg.Search.Engine.MaxTotalHits != 10000 {
		t.Errorf("expected max_total_hits=10000, got %d", cfg.Search.Engine.MaxTotalHits)
	}
	if cfg.Search.Cache.VerificationTTLHours != 336 {
		t.Errorf("expected verification_ttl_hours=336, got %d", cfg.Search.Cache.VerificationTTLHours)
	}
}

func TestGet_ReturnsSingleton(t *testing.T) {
	first := Get()
	second := Get()
	if first != second {
		t.Error("expected Get() to return the same instance on repeated calls")
	}
}
