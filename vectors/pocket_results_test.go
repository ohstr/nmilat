package vectors

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ohstr/nmilat/nipCP"
)

// K-POCKET-7: every committed resultToState case maps through MapStatus to its
// state, and the states are NIP-CP §Balance's table.
func TestKPOCKET7_ResultToState(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(committedDir, "pocket.json"))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Results []resultStateCase `json:"resultToState"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	spec := map[string]nipCP.State{
		"the wallet's own spend succeeded":                    nipCP.StateSpent,
		"tombstone, reason expired":                           nipCP.StateExpired,
		"tombstone, reason reclaimed":                         nipCP.StateReclaimed,
		"tombstone, reason redeemed":                          nipCP.StateSpent,
		"tombstone, reason transferred":                       nipCP.StateSpent,
		"tombstone, reason consolidated":                      nipCP.StateSpent,
		"tombstone, an unrecognised reason":                   nipCP.StateSpent,
		"tombstone, no reason":                                nipCP.StateSpent,
		"NOT_FOUND, proof signed by the entry's identity key": nipCP.StateReclaimed,
		"NOT_FOUND, cash entry, item made with its secret":    nipCP.StateReclaimed,
		"NOT_FOUND, proof signed by the connection key":       nipCP.StateUnknown,
		"NOT_FOUND, proof signed by another key":              nipCP.StateUnknown,
		"no answer (timeout)":                                 nipCP.StateUnknown,
	}
	if len(f.Results) != len(spec) {
		t.Fatalf("resultToState has %d cases, the table %d", len(f.Results), len(spec))
	}
	for _, c := range f.Results {
		in, err := c.statusInput()
		if err != nil {
			t.Fatal(err)
		}
		st, def := nipCP.MapStatus(in)
		if string(st) != c.State || def != c.Definitive {
			t.Errorf("%s: MapStatus = %s, %v; vector says %s, %v", c.Name, st, def, c.State, c.Definitive)
		}
		want, ok := spec[c.Name]
		if !ok {
			t.Errorf("%s: not in the table", c.Name)
			continue
		}
		if st != want || def != (want != nipCP.StateUnknown) {
			t.Errorf("%s: got %s (definitive %v), NIP-CP says %s", c.Name, st, def, want)
		}
	}
}
