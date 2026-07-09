// Package migrations runs versioned schema migrations against the relay
// package's embedded bbolt key-value store, tracking the applied version
// in a dedicated bucket.
package migrations

import (
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/rs/zerolog"
	bolt "go.etcd.io/bbolt"
)

var (
	// Bucket to store migration version
	MIGRATIONS_BUCKET = []byte("_migrations")
	// Key to store the current version
	VERSION_KEY = []byte("version")
)

type Migration interface {
	Version() uint64
	Description() string
	Up(tx *bolt.Tx) error
	Down(tx *bolt.Tx) error
}

type Manager struct {
	db         *bolt.DB
	migrations map[uint64]Migration
	logger     zerolog.Logger
}

// ManagerOption mutates a Manager at construction time.
type ManagerOption func(*Manager)

// WithLogger configures the logger used for migration progress logging.
// Defaults to zerolog.Nop() (silent).
func WithLogger(logger zerolog.Logger) ManagerOption {
	return func(m *Manager) {
		m.logger = logger
	}
}

func NewManager(db *bolt.DB, opts ...ManagerOption) *Manager {
	m := &Manager{
		db:         db,
		migrations: make(map[uint64]Migration),
		logger:     zerolog.Nop(),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

func (m *Manager) Register(migration Migration) {
	if _, exists := m.migrations[migration.Version()]; exists {
		panic(fmt.Sprintf("migration version %d already registered", migration.Version()))
	}
	m.migrations[migration.Version()] = migration
}

func (m *Manager) GetCurrentVersion() (uint64, error) {
	var version uint64
	err := m.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(MIGRATIONS_BUCKET)
		if b == nil {
			return nil // No migrations run yet, version 0
		}
		v := b.Get(VERSION_KEY)
		if v == nil {
			return nil
		}

		if len(v) != 8 {
			return fmt.Errorf("invalid version value length")
		}

		version = binary.BigEndian.Uint64(v)
		return nil
	})
	return version, err
}

func (m *Manager) SetVersion(tx *bolt.Tx, version uint64) error {
	b, err := tx.CreateBucketIfNotExists(MIGRATIONS_BUCKET)
	if err != nil {
		return err
	}

	vBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(vBytes, version)

	return b.Put(VERSION_KEY, vBytes)
}

func (m *Manager) Run() error {
	currentVersion, err := m.GetCurrentVersion()
	if err != nil {
		return fmt.Errorf("failed to get current migration version: %w", err)
	}

	var versions []uint64
	for v := range m.migrations {
		versions = append(versions, v)
	}
	sort.Slice(versions, func(i, j int) bool {
		return versions[i] < versions[j]
	})

	for _, v := range versions {
		if v > currentVersion {
			migration := m.migrations[v]
			m.logger.Info().Msgf("applying migration %d: %s", migration.Version(), migration.Description())

			err := m.db.Update(func(tx *bolt.Tx) error {
				if err := migration.Up(tx); err != nil {
					return err
				}
				return m.SetVersion(tx, v)
			})

			if err != nil {
				return fmt.Errorf("failed to apply migration %d: %w", v, err)
			}

			m.logger.Info().Msgf("migration %d applied successfully", v)
		}
	}

	return nil
}
