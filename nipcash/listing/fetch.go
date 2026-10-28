package listing

import (
	"slices"
	"strconv"

	"github.com/ohstr/nmilat/nip01"
)

// DefaultChunk is the authors chunk size TrustedFilters uses, and
// DefaultGlobalLimit GlobalFilter's limit.
const (
	DefaultChunk       = 100
	DefaultGlobalLimit = 500
)

// Trusted are the authors a wallet fetches first (§Fetching Listings): the
// user's follows and curators, the node identities they (and verified
// operators' 11191s) name, and the operators listings name.
type Trusted struct{ Follows, Curators, Nodes, Operators []string }

// TrustedFilters returns §Fetching Listings' trusted requests in its order:
// 31191 by follows and curators with #k 31190; 1984 by them with #p the node
// identities; 31190 by the node identities; kind 5 by the node identities with
// #k 31190; kinds 0 and 11191 by operators; kind 3 by follows with #p the
// operators; then kind 5 by follows and curators with #k 31191, so a withdrawn
// recommendation stops counting. Every authors list, and every #p list, is
// chunked by DefaultChunk;
// a request with no authors (or an empty #p) is left out. Relays, caching and
// since are the caller's.
func TrustedFilters(t Trusted) []nip01.SubscriptionFilter {
	people := dedupe(append(slices.Clone(t.Follows), t.Curators...))
	nodes, ops, follows := dedupe(t.Nodes), dedupe(t.Operators), dedupe(t.Follows)
	k31190, k31191 := strconv.Itoa(KindListing), strconv.Itoa(KindRecommendation)
	var out []nip01.SubscriptionFilter
	add := func(kinds []int, authors []string, tags map[string][]string) {
		for _, tv := range tags {
			if len(tv) == 0 {
				return
			}
		}
		// The one tag's values are chunked like authors, each authors chunk
		// paired with each values chunk.
		tagName, tagChunks := "", [][]string{nil}
		for k, v := range tags {
			tagName, tagChunks = k, ChunkAuthors(v, DefaultChunk)
		}
		for _, chunk := range ChunkAuthors(authors, DefaultChunk) {
			for _, tv := range tagChunks {
				f := nip01.SubscriptionFilter{Kinds: kinds, Authors: chunk}
				if tagName != "" {
					f.Tags = map[string][]string{tagName: tv}
				}
				out = append(out, f)
			}
		}
	}
	add([]int{KindRecommendation}, people, map[string][]string{"k": {k31190}})
	add([]int{KindReport}, people, map[string][]string{"p": nodes})
	add([]int{KindListing}, nodes, nil)
	add([]int{kindDeletion}, nodes, map[string][]string{"k": {k31190}})
	add([]int{0, KindOperatorOffers}, ops, nil)
	add([]int{3}, follows, map[string][]string{"p": ops})
	add([]int{kindDeletion}, people, map[string][]string{"k": {k31191}})
	return out
}

// GlobalFilter is the unreviewed request: every listing of both types on the
// given chains, up to limit (DefaultGlobalLimit when limit <= 0). A wallet shows
// what it adds apart from the trusted results, labelled unreviewed.
func GlobalFilter(chains []string, limit int) nip01.SubscriptionFilter {
	if limit <= 0 {
		limit = DefaultGlobalLimit
	}
	f := nip01.SubscriptionFilter{Kinds: []int{KindListing}, Limit: limit,
		Tags: map[string][]string{"t": {string(TypeCashOrder), string(TypeCircleWallet)}}}
	if len(chains) > 0 {
		f.Tags["n"] = slices.Clone(chains)
	}
	return f
}

// ChunkAuthors splits authors into chunks of at most n (DefaultChunk when
// n <= 0), in order.
func ChunkAuthors(authors []string, n int) [][]string {
	if n <= 0 {
		n = DefaultChunk
	}
	var out [][]string
	for c := range slices.Chunk(authors, n) {
		out = append(out, slices.Clone(c))
	}
	return out
}

func dedupe(s []string) []string {
	var out []string
	for _, v := range s {
		if v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}
