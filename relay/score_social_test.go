package relay

import (
	"context"
	"testing"

	"github.com/ohstr/nmilat/config"
	"github.com/ohstr/nmilat/nip01"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSocialScore_WeighsSendersByTheirOwnScore(t *testing.T) {
	f := newSocialFixture(t)
	trusted := newTestKey(t, 30)
	require.NoError(t, f.store.UpdateProfileMetrics(trusted.pub, func(m *ProfileMetrics) { m.BaseScore = 100 }))

	ghosts := &ProfileStats{RecdBySender: map[string]uint64{}}
	for i := 0; i < 10; i++ {
		ghosts.RecdBySender[newTestKey(t, 100+i).pub] = 1_000_000 // 1000 sats each
	}
	one := &ProfileStats{RecdBySender: map[string]uint64{trusted.pub: 10_000_000}}
	assert.Greater(t, f.store.SocialScore(one), f.store.SocialScore(ghosts),
		"one established sender outweighs ten unknown keys sending the same total")

	whale := &ProfileStats{RecdBySender: map[string]uint64{trusted.pub: 1_000_000_000_000}}
	capped := &ProfileStats{RecdBySender: map[string]uint64{trusted.pub: config.Get().Search.Social.PerSenderCap * 1000}}
	assert.Equal(t, f.store.SocialScore(capped), f.store.SocialScore(whale), "one sender is capped")

	followers := &ProfileStats{Followers: 1_000_000_000}
	assert.Equal(t, int64(config.Get().Search.Social.FollowersCap), f.store.SocialScore(followers))
}

func TestSocialScore_RefreshedForDirtyProfiles(t *testing.T) {
	f := newVerifyFixture(t, VerificationConfig{})
	var pushed = map[string]int64{}
	f.w.searchService = &MockSearchService{UpdateScoreFunc: func(_ context.Context, pk string, score int64) error {
		pushed[pk] = score
		return nil
	}}
	alice, bob := newTestKey(t, 10), newTestKey(t, 11)
	ev := &nip01.Event{PubKey: bob.pub, CreatedAt: 100, Kind: 3, Tags: [][]string{{"p", alice.pub}}}
	require.NoError(t, ev.Sign(bob.priv))
	InsertTestEvents(t, f.store, []*nip01.Event{ev})

	f.w.sweep()
	m, err := f.store.GetProfileMetrics(alice.pub)
	require.NoError(t, err)
	assert.Equal(t, int64(6), m.SocialScore, "20 x log10(2)")
	assert.Equal(t, m.TotalScore(), pushed[alice.pub])
	assert.Empty(t, f.store.TakeSocialDirty(10))
}
