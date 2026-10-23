package relay

import bolt "go.etcd.io/bbolt"

// The zap index lives in a bucket named by zapMeta's "active" key, or
// indexZaps when unset. RebuildIndex builds a new generation beside it and
// swaps the pointer in one transaction, so readers never see it empty.
var (
	zapMeta        = []byte{9, 'm'}
	zapActiveKey   = []byte("active")
	zapBuildingKey = []byte("building")
	zapGenKey      = []byte("gen")
	// coinsKey is the marker older versions read as "current" (zap or
	// social); it is kept while an index is live.
	coinsKey = []byte("coins")
)

// activeZapBucket returns the name of the bucket readers use.
func activeZapBucket(tx *bolt.Tx) []byte {
	if m := tx.Bucket(zapMeta); m != nil {
		if v := m.Get(zapActiveKey); v != nil {
			return append([]byte(nil), v...)
		}
	}
	return indexZaps
}
