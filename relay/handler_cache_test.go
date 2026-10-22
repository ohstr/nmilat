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
	"github.com/ohstr/nmilat/wire"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func TestCacheHandler_DisabledByDefault(t *testing.T) {
	tmpDB := "test_cache_disabled.db"
	_ = os.Remove(tmpDB)
	defer func() { _ = os.Remove(tmpDB) }()

	store, err := NewEventStore(tmpDB, &nip11.Limitation{}, WithEventStoreLogger(testlogger.New(t)))
	require.NoError(t, err)
	defer store.Close()

	// EnableTopZapped left at its zero value (false), even though PrivKey
	// is configured - the feature must not activate itself just because a
	// key happens to be present.
	sessCfg := &SessionConfig{
		PrivKey: "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c",
	}
	sc := NewSessionContext(store, &ClientInfo{RemoteAddr: "test"}, &nip11.Metadata{}, nil, nil, sessCfg)
	sess := &Session{SessionContext: sc}
	sess.replyer = &replyer{
		incoming: make(chan wire.SubscriptionResponse, 10),
		closeCh:  make(chan any),
	}

	handler := &CacheHandler{}
	req := &wire.RequestPacket{
		SubscriptionID: "sub1",
		Filters:        nip01.NewSubscriptionFilterGroup(),
	}
	req.Filters.Add(&nip01.SubscriptionFilter{
		Cache: json.RawMessage(`["top-zapped", {}]`),
	})

	handled, err := handler.Handle(context.Background(), sess, req)
	assert.True(t, handled)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disabled")
}

func TestCacheHandler(t *testing.T) {
	// Setup Store
	tmpDB := "test_cache.db"
	_ = os.Remove(tmpDB)
	defer func() { _ = os.Remove(tmpDB) }()

	store, err := NewEventStore(tmpDB, &nip11.Limitation{}, WithEventStoreLogger(testlogger.New(t)))
	require.NoError(t, err)
	defer store.Close()

	// Constants
	const (
		UserA = "000000000000000000000000000000000000000000000000000000000000000a"
		UserB = "000000000000000000000000000000000000000000000000000000000000000b"
	)

	// Insert some Zaps via Reindex-compatible logic or direct IndexZap
	err = store.db.Update(func(tx *bolt.Tx) error {
		now := uint64(time.Now().Unix())
		if err := store.IndexZap(tx, rawZap(t, 9521, UserA, "1000", now), 1); err != nil {
			return err
		}
		if err := store.IndexZap(tx, rawZap(t, 9735, UserB, "5000", now), 2); err != nil {
			return err
		}
		return nil
	})
	require.NoError(t, err)

	// Setup Session
	sessCfg := &SessionConfig{
		PrivKey:         "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c",
		EnableTopZapped: true,
	}
	sc := NewSessionContext(store, &ClientInfo{RemoteAddr: "test"}, &nip11.Metadata{}, nil, nil, sessCfg)
	sess := &Session{
		SessionContext: sc,
	}
	sess.replyer = &replyer{
		incoming: make(chan wire.SubscriptionResponse, 10),
		closeCh:  make(chan interface{}),
	}

	// Test CanHandle
	handler := &CacheHandler{}

	cacheFilter := &nip01.SubscriptionFilter{
		Cache: json.RawMessage(`["top-zapped", {"window": "1h", "limit": 10}]`),
	}

	req := &wire.RequestPacket{
		SubscriptionID: "sub1",
		Filters:        nip01.NewSubscriptionFilterGroup(),
	}
	req.Filters.Add(cacheFilter)

	assert.True(t, handler.CanHandle(req))

	// Execute Handler
	handled, err := handler.Handle(context.Background(), sess, req)
	assert.NoError(t, err)
	assert.True(t, handled)

	// Check responses
	close(sess.incoming)
	var responses []wire.SubscriptionResponse
	for resp := range sess.incoming {
		responses = append(responses, resp)
	}

	// Expect exactly 3 responses: EVENT, EOSE, CLOSED
	require.Len(t, responses, 3)

	// 1. EVENT (Kind 25521)
	respEv, ok := responses[0].(*wire.EventSubscriptionResponse)
	require.True(t, ok)
	assert.Equal(t, "sub1", respEv.SubscriptionID)

	var content map[string]interface{}
	err = json.Unmarshal(respEv.EventBytes, &content)
	require.NoError(t, err)
	assert.Equal(t, float64(25521), content["kind"])

	var stats []ZapStats
	err = json.Unmarshal([]byte(content["content"].(string)), &stats)
	require.NoError(t, err)
	// Both zaps count, sorted descending by total.
	require.Len(t, stats, 2)
	assert.Equal(t, UserB, stats[0].Pubkey)
	assert.Equal(t, uint64(5000), stats[0].TotalMLoki)
	assert.Equal(t, UserA, stats[1].Pubkey)
	assert.Equal(t, uint64(1000), stats[1].TotalMLoki)

	// 2. EOSE
	_, ok = responses[1].(*wire.EOSESubscriptionResponse)
	assert.True(t, ok)

	// 3. CLOSED
	respClosed, ok := responses[2].(*wire.ClosedSubscriptionResponse)
	require.True(t, ok)
	assert.Equal(t, "sub1", respClosed.SubscriptionID)
	assert.Contains(t, respClosed.Message, "completed")
}
