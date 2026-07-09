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

func TestCacheHandler_Defaults(t *testing.T) {
	// Setup Store
	tmpDB := "test_cache_defaults.db"
	os.Remove(tmpDB)
	defer os.Remove(tmpDB)

	store, err := NewEventStore(tmpDB, &nip11.Limitation{}, WithEventStoreLogger(testlogger.New(t)))
	require.NoError(t, err)
	defer store.Close()

	// Insert a Zap
	userA := "0000000000000000000000000000000000000000000000000000000000000001"
	zap1 := &nip01.Event{
		Kind:      9735,
		PubKey:    "0000000000000000000000000000000000000000000000000000000000000003",
		CreatedAt: uint64(time.Now().Unix()),
		Tags: [][]string{
			{"p", userA},
			{"amount", "1000"},
		},
	}
	zap1.ID = "0000000000000000000000000000000000000000000000000000000000000004"
	err = store.db.Update(func(tx *bolt.Tx) error {
		return store.insertWithIndexes(tx, zap1)
	})
	require.NoError(t, err)

	// Create Custom Session Config with defaults
	// defaultSessionConfig is unexported, so we construct manual config or use what we have
	cfg := &SessionConfig{
		DefaultCacheLimit:  5,
		DefaultCacheWindow: 1 * time.Hour,
		OutgoingBufferSize: 10,
		PrivKey:            "0acd12cbf0fb87cd13b17bc9b57dffd11b3870b407984cec5a4ce2a69b90268c",
		EnableTopZapped:    true,
	}

	sc := NewSessionContext(store, &ClientInfo{RemoteAddr: "test"}, &nip11.Metadata{}, nil, nil, cfg)
	sess := &Session{
		SessionContext: sc,
	}

	// Request without explicit window/limit
	req := &wire.RequestPacket{
		SubscriptionID: "sub1",
		Filters:        nip01.NewSubscriptionFilterGroup(),
	}
	// "args" is empty map
	req.Filters.Add(&nip01.SubscriptionFilter{
		Cache: json.RawMessage(`["top-zapped", {}]`),
	})

	handler := &CacheHandler{}

	// Execute
	handled, err := handler.Handle(context.Background(), sess, req)
	assert.NoError(t, err)
	assert.True(t, handled)

	// Since we inserted a Zap within 1h, it should be returned
	// and limit=5 is respected (though we have only 1)
	close(sess.incoming)
	var count int
	for range sess.incoming {
		count++
	}
	// Expect 3: EVENT (Kind 25521) + EOSE + CLOSED
	assert.Equal(t, 3, count, "should receive EVENT, EOSE and CLOSED")
}
