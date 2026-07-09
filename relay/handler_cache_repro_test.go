package relay

import (
	"encoding/json"
	"testing"

	"github.com/ohstr/nmilat/wire"
	"github.com/stretchr/testify/assert"
)

func TestCacheHandler_Reproduction(t *testing.T) {
	// precise JSON from user report
	rawJSON := `["REQ","cache-wg2f0",{"cache":["top-zapped",{"window":"24h","limit":5}]}]`

	var payload wire.RelayPayload
	err := json.Unmarshal([]byte(rawJSON), &payload)
	assert.NoError(t, err)

	rp, ok := payload.Packet.(*wire.RequestPacket)
	assert.True(t, ok, "payload should be a RequestPacket")

	handler := &CacheHandler{}
	canHandle := handler.CanHandle(rp)

	// Print what we parsed for debugging
	for i, f := range rp.Filters.GetAll() {
		t.Logf("Filter %d Cache: %s", i, string(f.Cache))
	}

	assert.True(t, canHandle, "CacheHandler should be able to handle this request")
}
