package vectors

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// committedDir is where the generated files are committed.
const committedDir = "../testdata/vectors"

// T18-02: regenerating every file reproduces the committed bytes exactly,
// and nothing else is committed beside them.
func TestT18_02_Drift(t *testing.T) {
	dir := t.TempDir()
	if err := WriteAll(dir); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, f := range Files() {
		want[f.Name] = true
		got, err := os.ReadFile(filepath.Join(dir, f.Name))
		if err != nil {
			t.Fatal(err)
		}
		committed, err := os.ReadFile(filepath.Join(committedDir, f.Name))
		if err != nil {
			t.Errorf("%s is not committed (go run ./cmd/export-vectors): %v", f.Name, err)
			continue
		}
		if !bytes.Equal(got, committed) {
			t.Errorf("%s drifted from the committed file; regenerate with go run ./cmd/export-vectors", f.Name)
		}
	}
	entries, err := os.ReadDir(committedDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !want[e.Name()] {
			t.Errorf("%s is committed but no builder writes it", e.Name())
		}
	}
}

// Every file name is unique and every build is deterministic.
func TestFiles_Deterministic(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range Files() {
		if seen[f.Name] {
			t.Errorf("%s listed twice", f.Name)
		}
		seen[f.Name] = true
		a, err := Build(f)
		if err != nil {
			t.Fatal(err)
		}
		b, err := Build(f)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("%s: two builds differ", f.Name)
		}
		var head struct{ Description, Source, Nmilat string }
		if err := json.Unmarshal(a, &head); err != nil || head.Description == "" || head.Source == "" || head.Nmilat != Version {
			t.Errorf("%s: header %+v (%v)", f.Name, head, err)
		}
	}
}

// T18-02: each committed file, read back, carries its KAT literals exactly
// (the values of the plan's KAT table, never recomputed here).
func TestT18_02_KATs(t *testing.T) {
	names := make([]string, 0, len(katChecks))
	for n := range katChecks {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(committedDir, name))
			if err != nil {
				t.Fatal(err)
			}
			var doc any
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.UseNumber()
			if err := dec.Decode(&doc); err != nil {
				t.Fatal(err)
			}
			for _, k := range katChecks[name] {
				got, err := k.find(doc)
				if err != nil {
					t.Errorf("%s: %v", k.id, err)
					continue
				}
				if fmt.Sprint(got) != k.want {
					t.Errorf("%s: %s = %v, want %s", k.id, k.path, got, k.want)
				}
			}
		})
	}
	for _, f := range Files() {
		if _, ok := katChecks[f.Name]; !ok && !noKATs[f.Name] {
			t.Errorf("%s has no KAT check", f.Name)
		}
	}
}

// noKATs are the files the plan lists no K-* literal for.
var noKATs = map[string]bool{
	"bolt11.json": true, "canonical-params.json": true, "cash-string.json": true, "nip01.json": true,
	"nip04.json": true, "nip19.json": true, "nip44.json": true, "private-join.json": true,
}

// kat is one literal: in the array at path's first element, the entry whose
// match field equals matchVal, field path[1:]... must print as want.
type kat struct {
	id, path string
	find     func(doc any) (any, error)
	want     string
}

// at walks doc by keys and [field=value,field=value] selectors, e.g.
// at("kats", "[id=K-CH-1]", "digest"). A missing last key reads as "" (an
// omitted empty field).
func at(steps ...string) func(doc any) (any, error) {
	return func(doc any) (any, error) {
		cur := doc
		for i, s := range steps {
			if len(s) > 2 && s[0] == '[' && s[len(s)-1] == ']' {
				arr, ok := cur.([]any)
				if !ok {
					return nil, fmt.Errorf("%s: not an array", s)
				}
				var found any
				for _, e := range arr {
					m, ok := e.(map[string]any)
					if ok && matches(m, s[1:len(s)-1]) {
						found = e
						break
					}
				}
				if found == nil {
					return nil, fmt.Errorf("no entry %s", s)
				}
				cur = found
				continue
			}
			m, ok := cur.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%s: not an object", s)
			}
			v, ok := m[s]
			if !ok {
				if i == len(steps)-1 {
					return "", nil
				}
				return nil, fmt.Errorf("no key %s", s)
			}
			cur = v
		}
		return cur, nil
	}
}

func matches(m map[string]any, conds string) bool {
	for _, c := range strings.Split(conds, ",") {
		field, val, _ := strings.Cut(c, "=")
		if fmt.Sprint(m[field]) != val {
			return false
		}
	}
	return true
}

func k(id, want string, steps ...string) kat {
	return kat{id: id, path: fmt.Sprint(steps), find: at(steps...), want: want}
}
