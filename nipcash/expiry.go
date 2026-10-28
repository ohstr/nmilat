package nipcash

import (
	"bytes"
	"encoding/json"
	"strconv"
)

// Expiry is an expires_at that a Hub omits for a bill that never expires. It
// decodes absent, null and 0 alike as never.
type Expiry struct {
	At      int64
	Present bool
}

// Never reports a bill that never expires.
func (e Expiry) Never() bool { return !e.Present || e.At == 0 }

// UnmarshalJSON reads a unix time, null or 0.
func (e *Expiry) UnmarshalJSON(b []byte) error {
	t := bytes.TrimSpace(b)
	if bytes.Equal(t, []byte("null")) {
		*e = Expiry{}
		return nil
	}
	v, err := strconv.ParseInt(string(t), 10, 64)
	if err != nil {
		return err
	}
	*e = Expiry{At: v, Present: v != 0}
	return nil
}

// IsZero reports never, so a field tagged `omitzero` is omitted for a bill
// that never expires: the Hub-side encoding NIP-CASH asks for. Every
// expires_at field of this package's results carries the tag.
func (e Expiry) IsZero() bool { return e.Never() }

// MarshalJSON writes the unix time, or null for never (a field tagged
// `omitzero` is omitted instead).
func (e Expiry) MarshalJSON() ([]byte, error) {
	if e.Never() {
		return []byte("null"), nil
	}
	return json.Marshal(e.At)
}

// ptr is the expiry as a *int64 (nil for never), for SliceLive.
func (e Expiry) ptr() *int64 {
	if e.Never() {
		return nil
	}
	v := e.At
	return &v
}
