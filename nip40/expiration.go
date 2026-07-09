// Package nip40 implements NIP-40: Expiration Timestamp, an "expiration"
// tag marking when relays should stop serving an event.
package nip40

import (
	"strconv"
	"time"

	"github.com/ohstr/nmilat/nip01"
)

const TagName = "expiration"

func GetExpiration(tags [][]string) (uint64, error) {
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == TagName {
			return strconv.ParseUint(tag[1], 10, 64)
		}
	}
	return 0, nil
}

func IsExpired(tags [][]string) bool {
	exp, err := GetExpiration(tags)
	if err != nil || exp == 0 {
		return false
	}
	return uint64(time.Now().Unix()) > exp
}

// AddExpiration sets ev's expiration tag to expiration, replacing any
// existing expiration tag in place rather than adding a duplicate.
func AddExpiration(ev *nip01.Event, expiration time.Time) {
	expStr := strconv.FormatInt(expiration.Unix(), 10)
	for i, tag := range ev.Tags {
		if len(tag) > 0 && tag[0] == TagName {
			ev.Tags[i] = []string{TagName, expStr}
			return
		}
	}
	ev.AddTag([]string{TagName, expStr})
}
