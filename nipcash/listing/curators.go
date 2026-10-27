package listing

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/ohstr/nmilat/nip01"
)

// ErrCuratorSet is a curator set ParseCuratorSet refuses.
var ErrCuratorSet = errors.New("listing: not a valid curator set")

// CuratorSet is a user's curators (§Curators): a NIP-51 follow set (kind 30000)
// with d CuratorSetD. Private reports items kept encrypted in content.
type CuratorSet struct {
	Curators []string
	Private  bool
}

// NewCuratorSet builds the unsigned curator set, with no title. Curators go
// private (a NIP-51 private item list encrypted to the user by encryptToSelf)
// whenever encryptToSelf is given or c.Private is set; only a nil encryptToSelf
// with c.Private false writes them as public p tags.
func NewCuratorSet(c CuratorSet, encryptToSelf func(string) (string, error)) (*nip01.Event, error) {
	tags := [][]string{{"d", CuratorSetD}}
	for _, p := range c.Curators {
		if !isHex64(p) {
			return nil, fmt.Errorf("%w: a curator is not a 64-hex pubkey", ErrCuratorSet)
		}
	}
	if !c.Private && encryptToSelf == nil {
		for _, p := range c.Curators {
			tags = append(tags, []string{"p", p})
		}
		return nip01.NewEvent(CuratorSetKind, "", tags...), nil
	}
	if encryptToSelf == nil {
		return nil, fmt.Errorf("%w: private curators need an encrypter", ErrCuratorSet)
	}
	items := make([][]string, 0, len(c.Curators))
	for _, p := range c.Curators {
		items = append(items, []string{"p", p})
	}
	plain, err := json.Marshal(items)
	if err != nil {
		return nil, err
	}
	content, err := encryptToSelf(string(plain))
	if err != nil {
		return nil, fmt.Errorf("%w: encrypt", ErrCuratorSet)
	}
	return nip01.NewEvent(CuratorSetKind, content, tags...), nil
}

// ParseCuratorSet reads a signed curator set: its public p tags, then its
// private ones when content is set and decryptFromSelf is given.
func ParseCuratorSet(ev *nip01.Event, decryptFromSelf func(string) (string, error)) (*CuratorSet, error) {
	if ev == nil || ev.Kind != CuratorSetKind || !hasTag(ev, "d", CuratorSetD) {
		return nil, fmt.Errorf("%w: kind or d", ErrCuratorSet)
	}
	if err := ev.Verify(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCuratorSet, err)
	}
	c := &CuratorSet{}
	add := func(tags [][]string) {
		for _, t := range tags {
			if len(t) >= 2 && t[0] == "p" && isHex64(t[1]) && !slices.Contains(c.Curators, t[1]) {
				c.Curators = append(c.Curators, t[1])
			}
		}
	}
	add(ev.Tags)
	if ev.Content != "" && decryptFromSelf != nil {
		plain, err := decryptFromSelf(ev.Content)
		if err != nil {
			return nil, fmt.Errorf("%w: decrypt", ErrCuratorSet)
		}
		var items [][]string
		if err := json.Unmarshal([]byte(plain), &items); err != nil {
			return nil, fmt.Errorf("%w: private items", ErrCuratorSet)
		}
		c.Private = true
		add(items)
	}
	return c, nil
}
