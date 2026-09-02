package relay

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/testlogger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func TestZapCacheWebIdentityScenarios(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "nmilat_zap_web_identity_test_*.db")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	store, err := NewEventStore(tmpFile.Name(), &nip11.Limitation{}, WithEventStoreLogger(testlogger.New(t)))
	require.NoError(t, err)
	defer store.Close()

	const (
		// ConnectionKeys are SHA256(platform:userID) — valid 64-hex, not Nostr pubkeys
		ConnKeyDiscord  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		ConnKeyTelegram = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		// Resolved Nostr pubkeys for the web-identity-linked users
		ResolvedDiscord  = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		ResolvedTelegram = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
		// A pure Nostr user who also receives a direct zap (same as ResolvedDiscord, to test merging)
		NostrUser = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	)

	now := time.Now()
	ts := uint64(now.Add(-1 * time.Hour).Unix())

	events := []*nip01.Event{
		// 1. Web-identity-linked with p[2] set and r tag → indexed under ResolvedDiscord
		{
			Kind:      5521,
			CreatedAt: ts,
			Tags: [][]string{
				{"p", ConnKeyDiscord, "discord"},
				{"r", ResolvedDiscord},
				{"amount", "1000"},
			},
		},
		// 2. Web-identity-linked without p[2] but r tag present → indexed under ResolvedTelegram
		{
			Kind:      5521,
			CreatedAt: ts,
			Tags: [][]string{
				{"p", ConnKeyTelegram},
				{"r", ResolvedTelegram},
				{"amount", "2000"},
			},
		},
		// 3. Web-identity-unlinked: p[2] = "discord", no r tag → NOT indexed
		{
			Kind:      5521,
			CreatedAt: ts,
			Tags: [][]string{
				{"p", ConnKeyDiscord, "discord"},
				{"amount", "9999"},
			},
		},
		// 4. Direct Nostr zap to the same pubkey as ResolvedDiscord → amounts should merge
		{
			Kind:      5521,
			CreatedAt: ts,
			Tags: [][]string{
				{"p", NostrUser, "nostr"},
				{"amount", "500"},
			},
		},
	}

	err = store.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(indexEvents)
		for i, ev := range events {
			evBytes, _ := json.Marshal(ev)
			b.Put(itob(uint64(i+1)), evBytes)
		}
		return nil
	})
	require.NoError(t, err)

	count, err := store.ReindexZaps(context.Background(), nil)
	require.NoError(t, err)
	// ReindexZaps counts all Kind 5521 events processed (4), regardless of whether
	// they were stored — web-identity-unlinked zaps are silently skipped by IndexZap.
	assert.Equal(t, 4, count)

	until := uint64(now.Unix())
	since := uint64(now.Add(-2 * time.Hour).Unix())
	stats, err := store.GetTopZapped(context.Background(), since, until, 10)
	require.NoError(t, err)

	// ResolvedTelegram: 2000
	// NostrUser (=ResolvedDiscord): 1000 (web-identity-linked) + 500 (direct) = 1500
	require.Len(t, stats, 2, "web-identity-unlinked entry must not appear")

	assert.Equal(t, ResolvedTelegram, stats[0].Pubkey)
	assert.Equal(t, uint64(2000), stats[0].TotalMLoki)

	assert.Equal(t, NostrUser, stats[1].Pubkey)
	assert.Equal(t, uint64(1500), stats[1].TotalMLoki, "web-identity-linked and direct zap amounts must merge")
}

func TestZapCacheScenarios(t *testing.T) {
	// Setup temporary DB
	tmpFile, err := os.CreateTemp("", "nmilat_zap_test_*.db")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	store, err := NewEventStore(tmpFile.Name(), &nip11.Limitation{}, WithEventStoreLogger(testlogger.New(t)))
	require.NoError(t, err)
	defer store.Close()

	// Constants
	const (
		UserA = "000000000000000000000000000000000000000000000000000000000000000a"
		UserB = "000000000000000000000000000000000000000000000000000000000000000b"
	)

	// Time anchors
	now := time.Now()
	timestampNow := uint64(now.Unix())
	timestamp1HourAgo := uint64(now.Add(-1 * time.Hour).Unix())
	timestamp2HoursAgo := uint64(now.Add(-2 * time.Hour).Unix())
	timestamp25HoursAgo := uint64(now.Add(-25 * time.Hour).Unix()) // Outside 24h window
	timestampFuture := uint64(now.Add(1 * time.Hour).Unix())       // Future

	// Test Events
	events := []*nip01.Event{
		// 1. User A: 1000 sats (Inside window) - Realistic Kind 5521
		{
			Kind:      5521,
			CreatedAt: timestamp1HourAgo,
			Tags:      [][]string{{"p", UserA}, {"description", `{"kind":5520,"tags":[["amount","1000"],["p","` + UserA + `"]]}`}},
			Content:   "Zap A 1",
		},
		// 2. User A: 500 sats (Inside window) - Realistic Kind 5521
		{
			Kind:      5521,
			CreatedAt: timestamp2HoursAgo,
			Tags:      [][]string{{"p", UserA}, {"description", `{"kind":5520,"tags":[["amount","500"],["p","` + UserA + `"]]}`}},
			Content:   "Zap A 2",
		},
		// 3. User B: 2000 sats (Inside window) - Realistic Kind 5521
		{
			Kind:      5521,
			CreatedAt: timestamp1HourAgo,
			Tags:      [][]string{{"p", UserB}, {"description", `{"kind":5520,"tags":[["amount","2000"],["p","` + UserB + `"]]}`}},
			Content:   "Zap B 1",
		},
		// 4. User A: 5000 sats (Outside window - Too old)
		{
			Kind:      5521,
			CreatedAt: timestamp25HoursAgo,
			Tags:      [][]string{{"p", UserA}, {"description", `{"kind":5520,"tags":[["amount","5000"]]}`}},
			Content:   "Zap A Old",
		},
		// 5. User B: 5000 sats (Outside window - Future)
		{
			Kind:      5521,
			CreatedAt: timestampFuture,
			Tags:      [][]string{{"p", UserB}, {"description", `{"kind":5520,"tags":[["amount","5000"]]}`}},
			Content:   "Zap B Future",
		},
		// 6. User C: Invalid kind (Not a zap)
		{
			Kind:      1,
			CreatedAt: timestamp1HourAgo,
			Tags:      [][]string{{"p", UserA}, {"amount", "99999"}},
			Content:   "Not a Zap",
		},
	}

	// Insert into DB directly (simulating raw storage)
	err = store.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(indexEvents)
		for i, ev := range events {
			evBytes, _ := json.Marshal(ev)
			// Use simple incrementing evsid
			b.Put(itob(uint64(i+1)), evBytes)
		}
		return nil
	})
	require.NoError(t, err)

	// Run ReindexZaps
	count, err := store.ReindexZaps(context.Background(), nil)
	require.NoError(t, err)
	// We expect 5 zaps to be indexed (even if outside query window, they are valid zaps)
	// The 6th event is Kind 1, so it shouldn't be indexed.
	assert.Equal(t, 5, count, "Should index 5 valid zap events")

	// Query Case 1: 24 Hour Window
	// Window: [now - 24h, now]
	start24h := uint64(now.Add(-24 * time.Hour).Unix())

	// Expected:
	// User A: 1000 + 500 = 1500
	// User B: 2000
	// User A's old zap (5000) is excluded.
	// User B's future zap (5000) is excluded (because query 'until' is 'now')

	stats, err := store.GetTopZapped(context.Background(), start24h, timestampNow, 10)
	require.NoError(t, err)

	// Validate Order (B > A)
	require.Len(t, stats, 2)

	// Rank 1: User B
	assert.Equal(t, UserB, stats[0].Pubkey)
	assert.Equal(t, uint64(2000), stats[0].TotalMLoki)

	// Rank 2: User A
	assert.Equal(t, UserA, stats[1].Pubkey)
	assert.Equal(t, uint64(1500), stats[1].TotalMLoki)

	// Query Case 2: All Time (technically just very old start)
	// Window: [0, now + 2h]
	// Should include the old zap, and the future zap
	statsAll, err := store.GetTopZapped(context.Background(), 0, timestampFuture+100, 10)
	require.NoError(t, err)

	// User A: 1500 + 5000 (old) = 6500
	// User B: 2000 + 5000 (future) = 7000
	require.Len(t, statsAll, 2)
	assert.Equal(t, UserB, statsAll[0].Pubkey)
	assert.Equal(t, uint64(7000), statsAll[0].TotalMLoki)
	assert.Equal(t, UserA, statsAll[1].Pubkey)
	assert.Equal(t, uint64(6500), statsAll[1].TotalMLoki)
}
