package relay

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip05"
	"github.com/ohstr/nmilat/nip11"
)

// nip05Handler serves a NIP-05 /.well-known/nostr.json identity document
// backed by kind:35555 identity events published to store. This is
// relay-serving infrastructure (it queries store's index directly); nip05
// itself has no dependency on relay — see nip05.BuildIdentityResponse for
// the pure event-to-response logic this handler wraps.
type nip05Handler struct {
	store *EventStore
	cfg   *nip11.Metadata
}

// NewNIP05Handler returns an http.Handler serving NIP-05 identity lookups
// (optionally filtered by a "name" query parameter) from the identity
// events already stored in store.
func NewNIP05Handler(store *EventStore, cfg *nip11.Metadata) http.Handler {
	return &nip05Handler{
		store: store,
		cfg:   cfg,
	}
}

func (h *nip05Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	response, err := h.findIdentities(r.Context(), strings.TrimSpace(r.URL.Query().Get("name")))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	jsonData, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Error generating JSON response", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(jsonData); err != nil {
		http.Error(w, "Error writing JSON response", http.StatusInternalServerError)
	}
}

func (h *nip05Handler) findIdentities(ctx context.Context, name string) (*nip05.IdentityResponse, error) {

	var wg sync.WaitGroup
	potEvent := make(chan *PotentialEvent)
	var dnsEvents []*nip01.Event

	filters := nip01.NewSubscriptionFilterGroup()
	filter := &nip01.SubscriptionFilter{
		Kinds:   []int{nip05.Kind},
		Authors: []string{h.cfg.PubKey},
		Tags:    make(map[string][]string, 1),
		Limit:   h.cfg.Limitation.MaxLimit,
	}
	if len(name) > 0 {
		filter.Tags["d"] = []string{name}
	} else {
		filter.Tags["d"] = []string{"_"}
	}
	filters.Add(filter)

	query, err := NewStoreQuery(h.store, filters)
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return

			case pe, ok := <-potEvent:
				if !ok {
					return
				}
				dnsEvent, err := h.store.FindEvent(pe.Evsid)
				if err != nil {
					continue
				}
				dnsEvents = append(dnsEvents, dnsEvent)
				wg.Done()
			}
		}
	}()

	_ = query.Fetch(ctx, potEvent, &wg, false)
	wg.Wait()
	close(potEvent)

	return nip05.BuildIdentityResponse(dnsEvents), nil
}
