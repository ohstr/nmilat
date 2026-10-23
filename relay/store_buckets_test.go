package relay

import "testing"

// Every top-level bucket needs its own name: two features sharing one
// read each other's keys as their own.
func TestBucketIDsAreUnique(t *testing.T) {
	buckets := map[string][]byte{
		"indexEvents":          indexEvents,
		"indexID":              indexID,
		"indexPubkey":          indexPubkey,
		"indexKind":            indexKind,
		"indexTag":             indexTag,
		"indexCreatedAt":       indexCreatedAt,
		"indexExpiration":      indexExpiration,
		"indexKindPubkey":      indexKindPubkey,
		"indexZaps":            indexZaps,
		"zapMeta":              zapMeta,
		"indexProfileMetrics":  indexProfileMetrics,
		"indexMembers":         indexMembers,
		"indexInviteClaims":    indexInviteClaims,
		"indexGroups":          indexGroups,
		"indexGroupInvites":    indexGroupInvites,
		"indexVerificationDue": indexVerificationDue,
		"socialMeta":           socialMeta,
		"socialDefault":        socialDefault,
		"indexCounters":        indexCounters,
		"storeMeta":            storeMeta,
	}
	seen := map[string]string{}
	for name, id := range buckets {
		if other, dup := seen[string(id)]; dup {
			t.Errorf("%s and %s share bucket id %v", name, other, id)
		}
		seen[string(id)] = name
	}
	// 10 was indexIdentities; old stores may still hold it.
	if name, used := seen[string([]byte{10})]; used {
		t.Errorf("%s reuses retired bucket id 10", name)
	}
}
