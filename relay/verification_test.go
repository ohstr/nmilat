package relay

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseLud16Metadata(t *testing.T) {
	tests := []struct {
		name           string
		metadata       string
		expectedChains int
	}{
		{
			name:           "Empty metadata",
			metadata:       "[]",
			expectedChains: 1, // Default Bitcoin
		},
		{
			name:           "Only plain text",
			metadata:       `[["text/plain", "Zap me"]]`,
			expectedChains: 1, // Default Bitcoin
		},
		{
			name:           "Bitcoin chain",
			metadata:       `[["text/plain", "Zap me"], ["chain/bitcoin", "sats"]]`,
			expectedChains: 1,
		},
		{
			name:           "Multiple chains",
			metadata:       `[["text/plain", "Zap me"], ["chain/bitcoin", "sats"], ["chain/flokicoin", "loki"]]`,
			expectedChains: 2,
		},
		{
			name:           "Flokicoin only",
			metadata:       `[["text/plain", "Zap me"], ["chain/flokicoin", "loki"]]`,
			expectedChains: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var metadata [][]interface{}
			err := json.Unmarshal([]byte(tt.metadata), &metadata)
			assert.NoError(t, err)

			chainCount := 0
			for _, item := range metadata {
				if len(item) > 0 {
					if tag, ok := item[0].(string); ok {
						if tag == "chain/bitcoin" || tag == "chain/flokicoin" || (len(tag) > 6 && tag[:6] == "chain/") {
							chainCount++
						}
					}
				}
			}

			actualChains := chainCount
			if actualChains == 0 {
				actualChains = 1
			}
			assert.Equal(t, tt.expectedChains, actualChains)
		})
	}
}
