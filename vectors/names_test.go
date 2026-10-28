package vectors

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// okName matches a case name that promises success.
var okName = regexp.MustCompile(`(?i)\b(fine|accepted|ok|okay)\b`)

// A case whose name says it succeeds must not expect an error.
func TestCaseNames_MatchExpectedResult(t *testing.T) {
	for _, f := range Files() {
		raw, err := os.ReadFile(filepath.Join(committedDir, f.Name))
		if err != nil {
			t.Fatal(err)
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		walkCases(v, func(name, errText string) {
			if okName.MatchString(name) && errText != "" {
				t.Errorf("%s: case %q says it succeeds but expects error %q", f.Name, name, errText)
			}
		})
	}
}

func walkCases(v any, visit func(name, errText string)) {
	switch x := v.(type) {
	case map[string]any:
		if name, ok := x["name"].(string); ok {
			e, _ := x["error"].(string)
			visit(name, e)
		}
		for _, c := range x {
			walkCases(c, visit)
		}
	case []any:
		for _, c := range x {
			walkCases(c, visit)
		}
	}
}
