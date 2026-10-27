package vectors

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ohstr/nmilat/internal/cashtest"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipcash/transport"
)

// K-POW-4: pow.json's relay rule is what the PoW relay double enforces.
func TestKPOW4_RelayRuleMatchesTheRelay(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(committedDir, "pow.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		RelayRule []powRelayCase `json:"relayRule"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.RelayRule) == 0 {
		t.Fatal("no relay rule cases")
	}
	r := cashtest.NewRelay(t)
	r.SetMinPow(1)
	for _, c := range f.RelayRule {
		r.SetPowClock(func() time.Time { return time.Unix(c.Now, 0) })
		priv, pub := cashtest.Keypair(t)
		ev := nip01.NewEvent(transport.KindPrivateRequest, "x")
		ev.PubKey = pub
		if c.Expiration != nil {
			ev.Tags = append(ev.Tags, []string{"expiration", strconv.FormatInt(*c.Expiration, 10)})
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := ev.Mine(ctx, 1); err != nil {
			cancel()
			t.Fatal(err)
		}
		cancel()
		if err := ev.Sign(priv); err != nil {
			t.Fatal(err)
		}
		if ok, msg := r.Publish(ev); ok != c.Accepted {
			t.Errorf("expiration %v at %d: relay accepted %v (%s), pow.json says %v", c.Expiration, c.Now, ok, msg, c.Accepted)
		}
	}
}
