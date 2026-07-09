package migrations

import (
	"os"
	"testing"

	bolt "go.etcd.io/bbolt"
)

func newTestDB(t *testing.T) *bolt.DB {
	t.Helper()
	f, err := os.CreateTemp("", "migrations_test_*.db")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	f.Close()
	t.Cleanup(func() { os.Remove(f.Name()) })

	db, err := bolt.Open(f.Name(), 0600, nil)
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

type fakeMigration struct {
	version     uint64
	description string
	applied     *bool
}

func (m *fakeMigration) Version() uint64     { return m.version }
func (m *fakeMigration) Description() string { return m.description }
func (m *fakeMigration) Up(tx *bolt.Tx) error {
	if m.applied != nil {
		*m.applied = true
	}
	return nil
}
func (m *fakeMigration) Down(tx *bolt.Tx) error { return nil }

func TestManager_GetCurrentVersion_DefaultsToZero(t *testing.T) {
	db := newTestDB(t)
	mgr := NewManager(db)

	v, err := mgr.GetCurrentVersion()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 0 {
		t.Errorf("expected version 0, got %d", v)
	}
}

func TestManager_Register_PanicsOnDuplicateVersion(t *testing.T) {
	db := newTestDB(t)
	mgr := NewManager(db)

	mgr.Register(&fakeMigration{version: 1, description: "first"})

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected a panic when registering a duplicate version")
		}
	}()
	mgr.Register(&fakeMigration{version: 1, description: "duplicate"})
}

func TestManager_Run_AppliesMigrationsInOrderAndPersistsVersion(t *testing.T) {
	db := newTestDB(t)
	mgr := NewManager(db)

	var appliedV1, appliedV2 bool
	mgr.Register(&fakeMigration{version: 2, description: "second", applied: &appliedV2})
	mgr.Register(&fakeMigration{version: 1, description: "first", applied: &appliedV1})

	if err := mgr.Run(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !appliedV1 || !appliedV2 {
		t.Fatalf("expected both migrations to be applied: v1=%v v2=%v", appliedV1, appliedV2)
	}

	v, err := mgr.GetCurrentVersion()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if v != 2 {
		t.Errorf("expected current version 2, got %d", v)
	}
}

func TestManager_Run_IsIdempotent(t *testing.T) {
	db := newTestDB(t)
	mgr := NewManager(db)

	countingMigration := &countingFakeMigration{version: 1, description: "counted"}
	mgr.Register(countingMigration)

	if err := mgr.Run(); err != nil {
		t.Fatalf("unexpected error on first run: %v", err)
	}
	if err := mgr.Run(); err != nil {
		t.Fatalf("unexpected error on second run: %v", err)
	}

	if countingMigration.calls != 1 {
		t.Errorf("expected migration to run exactly once across two Run() calls, got %d calls", countingMigration.calls)
	}
}

type countingFakeMigration struct {
	version     uint64
	description string
	calls       int
}

func (m *countingFakeMigration) Version() uint64     { return m.version }
func (m *countingFakeMigration) Description() string { return m.description }
func (m *countingFakeMigration) Up(tx *bolt.Tx) error {
	m.calls++
	return nil
}
func (m *countingFakeMigration) Down(tx *bolt.Tx) error { return nil }

func TestResetVerificationCacheMigration(t *testing.T) {
	db := newTestDB(t)
	bucketName := []byte("profile_metrics")

	err := db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketName)
		if err != nil {
			return err
		}
		return b.Put([]byte("pubkey1"), []byte(`{"base_score":10,"last_verified_at":12345}`))
	})
	if err != nil {
		t.Fatalf("failed to seed bucket: %v", err)
	}

	migration := &ResetVerificationCacheMigration{MetricsBucket: bucketName}
	if migration.Version() != 1 {
		t.Errorf("expected version 1, got %d", migration.Version())
	}
	if migration.Description() == "" {
		t.Error("expected a non-empty description")
	}

	err = db.Update(func(tx *bolt.Tx) error {
		return migration.Up(tx)
	})
	if err != nil {
		t.Fatalf("unexpected error running Up: %v", err)
	}

	err = db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketName).Get([]byte("pubkey1"))
		if v == nil {
			t.Fatal("expected the entry to still exist")
		}
		if string(v) != `{"base_score":10,"nip05_score":0,"lud16_score":0,"picture_score":0,"last_verified_at":0}` {
			t.Errorf("expected last_verified_at to be reset to 0, got: %s", v)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Down is a no-op; just make sure it doesn't error.
	if err := db.Update(func(tx *bolt.Tx) error { return migration.Down(tx) }); err != nil {
		t.Fatalf("unexpected error running Down: %v", err)
	}
}

func TestResetVerificationCacheMigration_NoBucket(t *testing.T) {
	db := newTestDB(t)
	migration := &ResetVerificationCacheMigration{MetricsBucket: []byte("does-not-exist")}

	err := db.Update(func(tx *bolt.Tx) error {
		return migration.Up(tx)
	})
	if err != nil {
		t.Fatalf("expected no error when the bucket doesn't exist, got: %v", err)
	}
}
