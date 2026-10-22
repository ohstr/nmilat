package nip77

import (
	"encoding/hex"
	"math/rand"
	"sort"
	"testing"
)

// randomSets builds a shared set plus client-only and server-only items,
// with timestamps drawn from a small range so many items share one.
func randomSets(seed int64, shared, clientOnly, serverOnly int) (client, server []Item, wantHave, wantNeed map[string]bool) {
	r := rand.New(rand.NewSource(seed))
	gen := func() Item {
		var it Item
		it.Timestamp = uint64(1_700_000_000 + r.Intn(5000))
		r.Read(it.ID[:])
		return it
	}
	wantHave, wantNeed = map[string]bool{}, map[string]bool{}
	for range shared {
		it := gen()
		client = append(client, it)
		server = append(server, it)
	}
	for range clientOnly {
		it := gen()
		client = append(client, it)
		wantHave[hex.EncodeToString(it.ID[:])] = true
	}
	for range serverOnly {
		it := gen()
		server = append(server, it)
		wantNeed[hex.EncodeToString(it.ID[:])] = true
	}
	sortItems(client)
	sortItems(server)
	return client, server, wantHave, wantNeed
}

func sortItems(items []Item) {
	sort.Slice(items, func(i, j int) bool { return items[i].Compare(items[j]) < 0 })
}

type syncResult struct {
	have, need   map[string]bool
	dupes        int
	rounds       int
	maxClientMsg int
	maxServerMsg int
}

// runSync reconciles client against server until the client's reply is
// complete, failing if any message is over its sender's limit.
func runSync(t *testing.T, client, server *Negentropy, maxRounds int) syncResult {
	t.Helper()
	res := syncResult{have: map[string]bool{}, need: map[string]bool{}}
	add := func(m map[string]bool, ids []string) {
		for _, id := range ids {
			if m[id] {
				res.dupes++
			}
			m[id] = true
		}
	}
	size := func(m *Message) int {
		b, err := m.ToBytes()
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		return len(b)
	}
	check := func(who string, m *Message, limit int) int {
		if limit > 0 {
			limit = max(limit, MinFrameSizeLimit)
		}
		n := size(m)
		if limit > 0 && n > limit {
			t.Fatalf("round %d: %s message is %d bytes, over the %d limit", res.rounds, who, n, limit)
		}
		return n
	}

	msg := client.Initiate()
	res.maxClientMsg = check("client", msg, client.FrameSizeLimit)
	for res.rounds = 1; res.rounds <= maxRounds; res.rounds++ {
		// Round-trip through the wire format, as a real peer would.
		msg = roundTrip(t, msg)
		reply, _, _, err := server.Reconcile(msg)
		if err != nil {
			t.Fatalf("round %d: server: %v", res.rounds, err)
		}
		res.maxServerMsg = max(res.maxServerMsg, check("server", reply, server.FrameSizeLimit))

		reply = roundTrip(t, reply)
		next, have, need, err := client.Reconcile(reply)
		if err != nil {
			t.Fatalf("round %d: client: %v", res.rounds, err)
		}
		add(res.have, have)
		add(res.need, need)
		res.maxClientMsg = max(res.maxClientMsg, check("client", next, client.FrameSizeLimit))
		if IsComplete(next) {
			return res
		}
		msg = next
	}
	t.Fatalf("no convergence within %d rounds", maxRounds)
	return res
}

func roundTrip(t *testing.T, m *Message) *Message {
	t.Helper()
	h, err := m.ToHex()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, err := FromHex(h)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

func sameSet(t *testing.T, what string, got, want map[string]bool) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: got %d ids, want %d", what, len(got), len(want))
	}
	for id := range want {
		if !got[id] {
			t.Errorf("%s: missing %s", what, id)
			return
		}
	}
}

func TestReconcileFrameSizeLimit(t *testing.T) {
	tests := []struct {
		name                         string
		shared, clientOnly, serverOn int
		clientLimit, serverLimit     int
	}{
		{"client empty", 0, 0, 20_000, DefaultFrameSizeLimit, DefaultFrameSizeLimit},
		{"server empty", 0, 20_000, 0, DefaultFrameSizeLimit, DefaultFrameSizeLimit},
		{"both sides differ", 10_000, 8_000, 8_000, DefaultFrameSizeLimit, DefaultFrameSizeLimit},
		{"mostly shared", 30_000, 500, 500, DefaultFrameSizeLimit, DefaultFrameSizeLimit},
		{"minimum limit", 2_000, 3_000, 3_000, MinFrameSizeLimit, MinFrameSizeLimit},
		{"unlimited server", 5_000, 6_000, 6_000, DefaultFrameSizeLimit, 0},
		{"unlimited client", 5_000, 6_000, 6_000, 0, DefaultFrameSizeLimit},
		{"different limits", 5_000, 6_000, 6_000, MinFrameSizeLimit, DefaultFrameSizeLimit},
	}
	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, s, wantHave, wantNeed := randomSets(int64(i+1), tc.shared, tc.clientOnly, tc.serverOn)
			client, server := New(c), New(s)
			client.FrameSizeLimit = tc.clientLimit
			server.FrameSizeLimit = tc.serverLimit

			res := runSync(t, client, server, 10_000)
			sameSet(t, "have", res.have, wantHave)
			sameSet(t, "need", res.need, wantNeed)
			if res.dupes != 0 {
				t.Errorf("%d ids reported twice", res.dupes)
			}
			t.Logf("rounds=%d max client=%dB server=%dB", res.rounds, res.maxClientMsg, res.maxServerMsg)
		})
	}
}

// Many seeds and sizes, small limit: exact sets every time.
func TestReconcileFrameSizeLimitRandom(t *testing.T) {
	for seed := int64(100); seed < 140; seed++ {
		r := rand.New(rand.NewSource(seed))
		shared, co, so := r.Intn(3000), r.Intn(3000), r.Intn(3000)
		c, s, wantHave, wantNeed := randomSets(seed, shared, co, so)
		client, server := New(c), New(s)
		client.FrameSizeLimit = MinFrameSizeLimit + r.Intn(20_000)
		server.FrameSizeLimit = MinFrameSizeLimit + r.Intn(20_000)

		res := runSync(t, client, server, 10_000)
		sameSet(t, "have", res.have, wantHave)
		sameSet(t, "need", res.need, wantNeed)
		if res.dupes != 0 {
			t.Errorf("seed %d: %d ids reported twice", seed, res.dupes)
		}
	}
}

// A limit below the floor still makes progress instead of looping.
func TestReconcileFrameSizeLimitFloor(t *testing.T) {
	c, s, wantHave, wantNeed := randomSets(7, 100, 2_000, 2_000)
	client, server := New(c), New(s)
	client.FrameSizeLimit = 10
	server.FrameSizeLimit = 10

	res := runSync(t, client, server, 10_000)
	sameSet(t, "have", res.have, wantHave)
	sameSet(t, "need", res.need, wantNeed)
	if res.maxClientMsg > MinFrameSizeLimit || res.maxServerMsg > MinFrameSizeLimit {
		t.Errorf("messages over the floor: client=%d server=%d", res.maxClientMsg, res.maxServerMsg)
	}
}

func TestNewDefaultsFrameSizeLimit(t *testing.T) {
	if got := New(nil).FrameSizeLimit; got != DefaultFrameSizeLimit {
		t.Errorf("FrameSizeLimit = %d, want %d", got, DefaultFrameSizeLimit)
	}
}

func TestSplitRangeThreshold(t *testing.T) {
	for _, tc := range []struct {
		items    int
		wantMode int
		wantN    int
	}{
		{31, 2, 1},
		{32, 1, 16},
		{1000, 1, 16},
	} {
		c, _, _, _ := randomSets(int64(tc.items), 0, tc.items, 0)
		neg := New(c)
		msg := &Message{ProtocolVersion: ProtocolVersion1, Ranges: []Range{
			{UpperBound: Bound{Timestamp: InfiniteTimestamp}, Mode: 1, Payload: computeFingerprint(nil)},
		}}
		resp, _, _, err := neg.Reconcile(msg)
		if err != nil {
			t.Fatal(err)
		}
		if len(resp.Ranges) != tc.wantN {
			t.Fatalf("%d items: got %d ranges, want %d", tc.items, len(resp.Ranges), tc.wantN)
		}
		for _, r := range resp.Ranges {
			if r.Mode != tc.wantMode {
				t.Fatalf("%d items: got mode %d, want %d", tc.items, r.Mode, tc.wantMode)
			}
		}
	}
}

func TestMinimalBound(t *testing.T) {
	a := Item{Timestamp: 10}
	b := Item{Timestamp: 20}
	if got := minimalBound(a, b); got.Timestamp != 20 || len(got.IDPrefix) != 0 {
		t.Errorf("different timestamps: got %+v", got)
	}

	c := Item{Timestamp: 20, ID: [32]byte{0xab, 0xcd, 0x01}}
	d := Item{Timestamp: 20, ID: [32]byte{0xab, 0xcd, 0x02}}
	got := minimalBound(c, d)
	if got.Timestamp != 20 || hex.EncodeToString(got.IDPrefix) != "abcd02" {
		t.Errorf("shared prefix: got ts=%d prefix=%x", got.Timestamp, got.IDPrefix)
	}
	if !ItemIsBeforeBound(c, got) || ItemIsBeforeBound(d, got) {
		t.Errorf("bound must split c and d")
	}
}

// A responder over the limit cuts its IdList at an item bound and ends with
// a fingerprint for the rest.
func TestResponderIdListCapped(t *testing.T) {
	s, _, _, _ := randomSets(3, 0, 2_000, 0)
	server := New(s)
	server.FrameSizeLimit = MinFrameSizeLimit

	empty, _ := encodeIdList(nil)
	msg := &Message{ProtocolVersion: ProtocolVersion1, Ranges: []Range{
		{UpperBound: Bound{Timestamp: InfiniteTimestamp}, Mode: 2, Payload: empty},
	}}
	resp, _, _, err := server.Reconcile(msg)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := resp.ToBytes()
	if len(b) > MinFrameSizeLimit {
		t.Fatalf("reply is %d bytes, over %d", len(b), MinFrameSizeLimit)
	}
	if len(resp.Ranges) != 2 || resp.Ranges[0].Mode != 2 || resp.Ranges[1].Mode != 1 {
		t.Fatalf("want IdList then Fingerprint, got %+v", modes(resp))
	}
	if resp.Ranges[1].UpperBound.Timestamp != InfiniteTimestamp {
		t.Errorf("remainder must run to infinity")
	}
	ids, _ := decodeIdList(resp.Ranges[0].Payload)
	if !ItemIsBeforeBound(s[len(ids)-1], resp.Ranges[0].UpperBound) || ItemIsBeforeBound(s[len(ids)], resp.Ranges[0].UpperBound) {
		t.Errorf("IdList bound must sit right after its last id")
	}
	if want := computeFingerprint(s[len(ids):]); hex.EncodeToString(resp.Ranges[1].Payload) != hex.EncodeToString(want) {
		t.Errorf("remainder fingerprint must cover the items not listed")
	}
}

// A fully matching reply carries no ranges, which IsComplete reads as done.
func TestReconcileMatchIsEmpty(t *testing.T) {
	items, _, _, _ := randomSets(5, 0, 500, 0)
	client, server := New(items), New(items)
	resp, _, _, err := server.Reconcile(client.Initiate())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Ranges) != 0 || !IsComplete(resp) {
		t.Errorf("want an empty, complete reply, got %v", modes(resp))
	}
}

func modes(m *Message) []int {
	out := make([]int, len(m.Ranges))
	for i, r := range m.Ranges {
		out[i] = r.Mode
	}
	return out
}
