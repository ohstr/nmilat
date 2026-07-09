package nip40

import (
	"strconv"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

func TestGetExpiration_NoTag(t *testing.T) {
	exp, err := GetExpiration([][]string{{"p", "somepubkey"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp != 0 {
		t.Errorf("expected 0, got %d", exp)
	}
}

func TestGetExpiration_ValidTag(t *testing.T) {
	exp, err := GetExpiration([][]string{{TagName, "1700000000"}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp != 1700000000 {
		t.Errorf("expected 1700000000, got %d", exp)
	}
}

func TestGetExpiration_InvalidValue(t *testing.T) {
	_, err := GetExpiration([][]string{{TagName, "not-a-number"}})
	if err == nil {
		t.Fatal("expected an error for a non-numeric expiration value")
	}
}

func TestAddExpiration(t *testing.T) {
	ev := &nip01.Event{Tags: [][]string{{"p", "somepubkey"}}}
	when := time.Unix(1700000000, 0)

	AddExpiration(ev, when)

	exp, err := GetExpiration(ev.Tags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp != 1700000000 {
		t.Errorf("expected 1700000000, got %d", exp)
	}
	if len(ev.Tags) != 2 {
		t.Errorf("expected the existing tag to be preserved alongside the new one, got %v", ev.Tags)
	}
}

func TestAddExpiration_ReplacesExisting(t *testing.T) {
	ev := &nip01.Event{Tags: [][]string{{TagName, "1600000000"}}}

	AddExpiration(ev, time.Unix(1700000000, 0))

	if len(ev.Tags) != 1 {
		t.Fatalf("expected the old expiration tag to be replaced, not duplicated, got %v", ev.Tags)
	}
	exp, err := GetExpiration(ev.Tags)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exp != 1700000000 {
		t.Errorf("expected 1700000000, got %d", exp)
	}
}

func TestIsExpired(t *testing.T) {
	past := time.Now().Add(-time.Hour).Unix()
	future := time.Now().Add(time.Hour).Unix()

	tests := []struct {
		name string
		tags [][]string
		want bool
	}{
		{"no expiration tag", nil, false},
		{"expired in the past", [][]string{{TagName, strconv.FormatInt(past, 10)}}, true},
		{"expires in the future", [][]string{{TagName, strconv.FormatInt(future, 10)}}, false},
		{"malformed value treated as not expired", [][]string{{TagName, "garbage"}}, false},
		{"zero value treated as not expired", [][]string{{TagName, "0"}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsExpired(tt.tags); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}
