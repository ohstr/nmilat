package relay

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/search"
	"github.com/ohstr/nmilat/wire"
)

func TestPacketFlow(t *testing.T) {

	esr := reflect.TypeOf(&wire.EventSubscriptionResponse{})
	eose := reflect.TypeOf(&wire.EOSESubscriptionResponse{})
	close := reflect.TypeOf(&wire.ClosedSubscriptionResponse{})

	expectedPackets := []reflect.Type{esr, esr, esr, eose, esr, esr, esr, esr, esr, close}

	store := newStoreWithEvents(t, CreateEvents(t, 3, 1))

	session := NewSessionContext(store, &ClientInfo{}, &nip11.Metadata{}, nil, nil, nil)
	sess := &Session{SessionContext: session}
	ctx := context.WithValue(context.Background(), sessionContextKey{}, sess)

	req := &wire.RequestPacket{
		SubscriptionID: "xx-xxxxxxxxxx",
		Filters:        CreateFilter([]int{}, 100),
	}

	go func() { _ = sess.ProcessPacket(ctx, req) }()

	for i, ptype := range expectedPackets {

		select {
		case packet := <-session.incoming:

			rcvType := reflect.TypeOf(packet)

			if ptype != rcvType {
				t.Fatalf("unexpected type, got=%v expected=%v", ptype, rcvType)
			}

			if ptype == eose {
				InsertTestEvents(t, store, CreateEvents(t, 5, 1))
			}

			if i == len(expectedPackets)-2 {
				closePacket := &wire.ClosePacket{
					SubscriptionID: req.SubscriptionID,
				}

				go func() { _ = sess.ProcessPacket(ctx, closePacket) }()
			}

		case <-time.After(time.Second * 5):
			t.Fatalf("timeout, expected packet = %v", ptype)
		}
	}
}

func TestPacketPayloads(t *testing.T) {

	tests := createPacketPayloadCases()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := json.Unmarshal([]byte(test.strObject), &test.instance)
			if err != nil {
				t.Fatal(err)
			}

			strBytes, err := json.Marshal(test.instance)
			if err != nil {
				t.Fatal(err)
			}

			if string(strBytes) != test.strObject {
				t.Fatalf("mismatch unmarshal versions")
			}
		})
	}

}

func TestPacketRequest(b *testing.T) {

	store := OpenBenchStore(b)
	tests := CreateTestCases()
	defer store.Close()

	for _, test := range tests {
		b.Run(test.Name, func(b *testing.T) {
			processPacketCase(b, store, test)
		})

	}
}

func TestPacketSubscriptionDuplicated(t *testing.T) {

	store := newStoreWithEvents(t, CreateEvents(t, 1, 1))

	session := NewSessionContext(store, &ClientInfo{}, &nip11.Metadata{}, nil, nil, nil)
	sess := &Session{SessionContext: session}
	ctx := context.WithValue(context.Background(), sessionContextKey{}, sess)

	go func() {
		for i := 0; i < 2; i++ {
			req := &wire.RequestPacket{
				SubscriptionID: "xx-xxxxxxxxxx",
				Filters:        CreateFilter([]int{2}, 100),
			}
			go func() { _ = sess.ProcessPacket(ctx, req) }()
			time.Sleep(time.Second * 1)
		}

		req := &wire.RequestPacket{
			SubscriptionID: "xx-xxxxxxxxxx",
			Filters:        CreateFilter([]int{1}, 100),
		}
		go func() { _ = sess.ProcessPacket(ctx, req) }()
	}()

	for {
		select {
		case e := <-session.incoming:
			if _, ok := e.(*wire.EventSubscriptionResponse); ok {
				if size := session.subscriptions.Size(); size != 1 {
					t.Fatalf("unexpected subs count, got=%d", size)
				}
				return
			}

		case <-session.closeCh:
			t.Fatal("unexpected signal")
		}
	}
}

func BenchmarkPacketRequest(b *testing.B) {

	store := OpenBenchStore(b)
	tests := CreateTestCases()
	defer store.Close()

	for _, test := range tests {
		b.Run(test.Name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				processPacketCase(b, store, test)
			}
		})
	}
}

func BenchmarkPacketUnmarshal(b *testing.B) {

	tests := createPacketPayloadCases()

	for _, test := range tests {
		b.Run(test.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				err := json.Unmarshal([]byte(test.strObject), &test.instance)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}

}

func processPacketCase(b testing.TB, store *EventStore, test ScanTestCase) {

	session := NewSessionContext(store, &ClientInfo{}, &nip11.Metadata{}, nil, nil, nil)
	sess := &Session{SessionContext: session}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), sessionContextKey{}, sess))

	filters := nip01.NewSubscriptionFilterGroup()
	filters.Add(test.SubscriptionFilter)

	rp := &wire.RequestPacket{
		SubscriptionID: "sub-xxx",
		Filters:        filters,
	}

	go func() { _ = sess.ProcessPacket(ctx, rp) }()

	var counter int

loop:
	for {
		select {
		case res := <-session.incoming:
			if _, ok := res.(*wire.EOSESubscriptionResponse); ok {
				break loop
			}
			counter++

		case <-time.After(time.Second * 1):
			b.Fatal("timeout")
		}
	}

	if counter != test.Expected {
		b.Fatalf("unexpected counter got=%d want=%d", counter, test.Expected)
	}

	cancel()

}

type PacketPayloadCase struct {
	name      string
	strObject string
	instance  interface{}
}

func createPacketPayloadCases() []*PacketPayloadCase {
	event := `["EVENT","sub-xxx",{"id":"5a4565594da42453b1302bd86ecd29fab2dff36997cdc252c0cde606ae57bf5e","pubkey":"3c1db3dd55e2ff09ba5317dd8eec2339797e9e2ddf74591172735c47f3a2ad6e","created_at":441766861,"kind":1,"tags":[["e","252f10c83610ebca1a059c0bae8255eba2f95be4d1d7bcfa89d7248a82d9f111","ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"],["p","e3b98a4da31a127d4bde6e43033f66ba274cab0eb7eb1c70ec41402bf6273dd8","594e519ae499312b29433b7dd8a97ff068defcba9755b6d5d00e84c524d67b06"]],"content":"content","sig":"c943e18705f60308f2e1b7d895c07c29493045dd64ca828b9d891b689fc3d4cb15739c6a1f2d848541001d5e0b6fdd8784d1c3fdbc3b2b715a63b648a66b535f"}]`
	close := `["CLOSED","sub-xxx","ok"]`
	eose := `["EOSE","sub-xxx"]`
	ok := `["OK","5a4565594da42453b1302bd86ecd29fab2dff36997cdc252c0cde606ae57bf5e",true,"ok"]`
	notice := `["NOTICE","ok"]`

	tests := []*PacketPayloadCase{
		{"event", event, &wire.EventSubscriptionResponse{}},
		{"close", close, &wire.ClosedSubscriptionResponse{}},
		{"eose", eose, &wire.EOSESubscriptionResponse{}},
		{"ok", ok, &wire.OkSubscriptionResponse{}},
		{"notice", notice, &wire.NoticeSubscriptionResponse{}},
	}

	return tests
}

func TestRunEventValidators(t *testing.T) {
	kind := 99999
	count := 0
	RegisterEventValidator(kind, func(_ context.Context, ev *nip01.Event) error {
		if ev.Kind != kind {
			t.Fatalf("unexpected kind, got=%d", ev.Kind)
		}
		count++
		return nil
	})

	event := &nip01.Event{Kind: kind}
	if err := runEventValidators(context.Background(), event); err != nil {
		t.Fatalf("expected no error, got=%v", err)
	}
	if count != 1 {
		t.Fatalf("validator not invoked, got=%d", count)
	}
}

// --- Search Integration Tests ---

type MockSearchService struct {
	IndexProfileFunc            func(ctx context.Context, doc *search.ProfileDocument) error
	FindProfilesFunc            func(ctx context.Context, query string, limit int) ([]string, error)
	DeleteProfileFunc           func(ctx context.Context, pubkey string) error
	InitializeFunc              func(ctx context.Context) error
	ShutdownFunc                func(ctx context.Context) error
	UpdateScoreFunc             func(ctx context.Context, pubkey string, score int64) error
	IndexProfileWithMetricsFunc func(ctx context.Context, profile *search.ProfileDocument, getMetricsFunc func(pubkey string) (int64, error)) error
	DeleteIndexFunc             func(ctx context.Context) error
}

func (m *MockSearchService) IndexProfile(ctx context.Context, doc *search.ProfileDocument) error {
	if m.IndexProfileFunc != nil {
		return m.IndexProfileFunc(ctx, doc)
	}
	return nil
}

func (m *MockSearchService) FindProfiles(ctx context.Context, query string, limit int) ([]string, error) {
	if m.FindProfilesFunc != nil {
		return m.FindProfilesFunc(ctx, query, limit)
	}
	return nil, nil
}

func (m *MockSearchService) DeleteProfile(ctx context.Context, pubkey string) error {
	if m.DeleteProfileFunc != nil {
		return m.DeleteProfileFunc(ctx, pubkey)
	}
	return nil
}

func (m *MockSearchService) Initialize(ctx context.Context) error {
	if m.InitializeFunc != nil {
		return m.InitializeFunc(ctx)
	}
	return nil
}

func (m *MockSearchService) Shutdown(ctx context.Context) error {
	if m.ShutdownFunc != nil {
		return m.ShutdownFunc(ctx)
	}
	return nil
}

func (m *MockSearchService) UpdateScore(ctx context.Context, pubkey string, score int64) error {
	if m.UpdateScoreFunc != nil {
		return m.UpdateScoreFunc(ctx, pubkey, score)
	}
	return nil
}

func (m *MockSearchService) IndexProfileWithMetrics(ctx context.Context, profile *search.ProfileDocument, getMetricsFunc func(pubkey string) (int64, error)) error {
	if m.IndexProfileWithMetricsFunc != nil {
		return m.IndexProfileWithMetricsFunc(ctx, profile, getMetricsFunc)
	}
	return m.IndexProfile(ctx, profile)
}

func (m *MockSearchService) DeleteIndex(ctx context.Context) error {
	if m.DeleteIndexFunc != nil {
		return m.DeleteIndexFunc(ctx)
	}
	return nil
}

func TestProcessEvent_SearchIndexing(t *testing.T) {
	t.Skip("Skipping write path test due to signing complexity without key access")
}

func TestProcessRequest_SearchFilter(t *testing.T) {
	store := newStoreWithEvents(t, []*nip01.Event{})

	called := make(chan struct{})
	mockSearch := &MockSearchService{
		FindProfilesFunc: func(ctx context.Context, query string, limit int) ([]string, error) {
			if limit != 100 {
				t.Errorf("expected limit=100, got=%d", limit)
			}
			if query == "alice" {
				close(called) // Signal success
				return []string{"pubkey1", "pubkey2"}, nil
			}
			return nil, nil
		},
	}

	var svc search.Service = mockSearch
	session := NewSessionContext(store, &ClientInfo{}, &nip11.Metadata{}, svc, nil, nil)
	sess := &Session{SessionContext: session}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), sessionContextKey{}, sess))
	defer cancel()

	// REQ with search
	filters := nip01.NewSubscriptionFilterGroup()
	f := &nip01.SubscriptionFilter{
		Kinds:  []int{0},
		Search: "alice",
	}
	filters.Add(f)

	req := &wire.RequestPacket{
		SubscriptionID: "sub1",
		Filters:        filters,
	}

	// Run process. It should trigger FindProfiles
	go func() { _ = sess.ProcessPacket(ctx, req) }()

	// Wait for call
	select {
	case <-called:
		// Success! Interception worked.
	case <-time.After(1 * time.Second):
		t.Fatal("FindProfiles was not called (timeout)")
	}
}

func TestProcessRequest_SearchFilter_NoSearchService(t *testing.T) {
	store := newStoreWithEvents(t, []*nip01.Event{})

	// No search service wired up (search disabled in config) — nil is a
	// valid Service, unlike the mock in TestProcessRequest_SearchFilter.
	session := NewSessionContext(store, &ClientInfo{}, &nip11.Metadata{}, nil, nil, nil)
	sess := &Session{SessionContext: session}
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), sessionContextKey{}, sess))
	defer cancel()

	filters := nip01.NewSubscriptionFilterGroup()
	filters.Add(&nip01.SubscriptionFilter{
		Kinds:  []int{0},
		Search: "alice",
	})

	req := &wire.RequestPacket{
		SubscriptionID: "sub1",
		Filters:        filters,
	}

	go func() { _ = sess.ProcessPacket(ctx, req) }()

	select {
	case packet := <-session.incoming:
		closed, ok := packet.(*wire.ClosedSubscriptionResponse)
		if !ok {
			t.Fatalf("expected ClosedSubscriptionResponse, got %T", packet)
		}
		if closed.SubscriptionID != req.SubscriptionID {
			t.Errorf("expected subscription id=%q, got=%q", req.SubscriptionID, closed.SubscriptionID)
		}
		if closed.Message != "unsupported: search is not enabled on this relay" {
			t.Errorf("unexpected CLOSED message: %q", closed.Message)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("expected a CLOSED response (timeout)")
	}
}
