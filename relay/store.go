package relay

import (
	"bytes"
	"container/heap"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip09"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/nip16"
	"github.com/ohstr/nmilat/nip33"
	"github.com/ohstr/nmilat/relay/migrations"

	// "github.com/ohstr/nmilat/nip40" // Inlined to avoid cycle
	"github.com/ohstr/nmilat/nip77"
	"github.com/ohstr/nmilat/utils"
	"github.com/rs/zerolog"
	bolt "go.etcd.io/bbolt"
)

var (
	ErrEventDuplicated = errors.New("already have this event")
	ErrStoreClosed     = errors.New("store is closed")
	ErrEventNotFound   = errors.New("event not found")

	indexEvents      = []byte{1}
	indexID          = []byte{2}
	indexPubkey      = []byte{3}
	indexKind        = []byte{4}
	indexTag         = []byte{5}
	indexCreatedAt   = []byte{6}
	indexExpiration  = []byte{7}
	indexKindPubkey  = []byte{8}
	indexZaps        = []byte{9}
	// 10 was indexIdentities, removed as dead (never read anywhere).
	indexProfileMetrics = []byte{11}

	maxUint64Bytes = itob(0xFFFFFFFFFFFFFFFF)
)

const (
	defaultMaxLimit         = 10_000_000 // 500
	defaultMaxIndexableTags = 5
	filterMinLimit          = 1
)

//////

type EventInsertTask struct {
	events []*nip01.Event
	errors chan error
	done   chan struct{}
}

func NewEventInsertTask(events []*nip01.Event) *EventInsertTask {
	return &EventInsertTask{
		events: events,
		// Buffered so Done() can never block: Execute's ctx.Done()/closeCh
		// branches call Done() synchronously, before the caller's own
		// listening select has a chance to start, and an abandoned task's
		// eventual Done() call (from ExecuteBatch) may have no reader left
		// at all.
		errors: make(chan error, 1),
		done:   make(chan struct{}),
	}
}

func (eit *EventInsertTask) Execute(store *EventStore) error {
	for _, ev := range eit.events {
		err := store.db.Update(func(tx *bolt.Tx) error {
			if err := store.checkEventDuplication(tx, ev); err != nil {
				return err
			}
			return store.insert(tx, ev)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (eit *EventInsertTask) Done(err error) {
	if err != nil {
		eit.errors <- err
	} else {
		close(eit.done)
	}
}

func (eit *EventInsertTask) Completed() <-chan struct{} {
	return eit.done
}

func (eit *EventInsertTask) Errors() <-chan error {
	return eit.errors
}

////

type EventDeleteTask struct {
	pes    []*PotentialEvent
	errors chan error
	done   chan struct{}
}

func NewEventDeleteTask(pes []*PotentialEvent) *EventDeleteTask {
	return &EventDeleteTask{
		pes:    pes,
		// Buffered: see the matching comment in NewEventInsertTask.
		errors: make(chan error, 1),
		done:   make(chan struct{}),
	}
}

func (edt *EventDeleteTask) Execute(store *EventStore) error {
	return store.db.Update(func(tx *bolt.Tx) error {
		return store.deleteAll(tx, edt.pes)
	})

}

func (edt *EventDeleteTask) Done(err error) {
	if err != nil {
		edt.errors <- err
	} else {
		close(edt.done)
	}
}

func (edt *EventDeleteTask) Completed() <-chan struct{} {
	return edt.done
}

func (edt *EventDeleteTask) Errors() <-chan error {
	return edt.errors
}

///

type Task interface {
	Execute(store *EventStore) error
	Done(err error)
}

type EventStore struct {
	db            *bolt.DB
	taskQueue     chan Task
	closeCh       chan interface{}
	closer        sync.Once
	// workersWg tracks handleTasks/startHousekeeper goroutines, all of which
	// touch db. Close waits on it before closing db, so no background
	// goroutine can still be mid-Update (or about to start one) once db is
	// actually closed -- see Close's comment for what that race caused.
	workersWg     sync.WaitGroup
	limitation    *nip11.Limitation
	workers       int
	batchSize     int
	batchInterval time.Duration
	logger        zerolog.Logger
}

func NewEventStore(path string, limitation *nip11.Limitation, opts ...EventStoreOption) (*EventStore, error) {
	cfg := defaultEventStoreConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.TaskQueueSize <= 0 {
		cfg.TaskQueueSize = defaultEventStoreConfig().TaskQueueSize
	}
	if cfg.WorkerCount <= 0 {
		cfg.WorkerCount = 1
	}

	options := &bolt.Options{
		Timeout: 3 * time.Second,
	}

	db, err := bolt.Open(path, 0600, options)
	if err != nil {
		return nil, fmt.Errorf("failed to open db:%s reason: %w", path, err)
	}

	// Run migrations
	mgr := migrations.NewManager(db, migrations.WithLogger(cfg.Logger))
	mgr.Register(&migrations.ResetVerificationCacheMigration{
		MetricsBucket: indexProfileMetrics,
	})

	if err := mgr.Run(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	if err := db.Update(func(tx *bolt.Tx) error {
		buckets := [][]byte{indexEvents, indexID, indexPubkey, indexKind, indexTag, indexCreatedAt, indexKindPubkey, indexExpiration}
		for _, bucketName := range buckets {
			_, err := tx.CreateBucketIfNotExists(bucketName)
			if err != nil {

				return err
			}
		}
		return nil
	}); err != nil {
		db.Close()
		return nil, err
	}

	if limitation.MaxLimit == 0 {
		limitation.MaxLimit = defaultMaxLimit
	}

	if limitation.MaxIndexableTags == 0 {
		limitation.MaxIndexableTags = defaultMaxIndexableTags
	}

	es := &EventStore{
		db:            db,
		taskQueue:     make(chan Task, cfg.TaskQueueSize),
		closeCh:       make(chan interface{}),
		limitation:    limitation,
		workers:       cfg.WorkerCount,
		batchSize:     cfg.BatchSize,
		batchInterval: cfg.BatchInterval,
		logger:        cfg.Logger,
	}

	es.startWorkers()

	return es, nil
}

func (s *EventStore) Name() string {
	return s.db.Path()
}

// Db returns the underlying bbolt handle, for an embedder's own buckets
// sharing this file. Never touch this package's own buckets through it —
// go through Execute/Task instead, which enforces dedup, replaceable-event
// handling, and index consistency. Unusable once Close has been called.
func (s *EventStore) Db() *bolt.DB {
	return s.db
}

// Close stops accepting new tasks and shuts down the store, waiting for
// every handleTasks/housekeeper goroutine to exit before closing db. Those
// goroutines race db.Update/db.View against closeCh, so closing db early
// can hit one already past that check — Execute on a mid-close bbolt
// handle hangs instead of erroring, blocking its caller forever.
func (s *EventStore) Close() {
	s.closer.Do(func() {
		close(s.closeCh)
	})

	s.workersWg.Wait()

	if s.db != nil {
		s.db.Close()
	}
}

// ExecuteBatch commits multiple tasks in a single transaction
func (s *EventStore) ExecuteBatch(tasks []Task) {
	if len(tasks) == 0 {
		return
	}

	taskErrors := make([]error, len(tasks))

	// Use a single transaction for the whole batch
	err := s.db.Update(func(tx *bolt.Tx) error {
		for i, task := range tasks {
			var err error
			switch t := task.(type) {
			case *EventInsertTask:
				for _, ev := range t.events {
					if err = s.checkEventDuplication(tx, ev); err != nil {
						if errors.Is(err, ErrEventDuplicated) {
							// Record duplication error but continue batch
							taskErrors[i] = err
							err = nil
							continue // Skip insert for this event
						}
						// other errors might be fatal (e.g. storage error)
						return err
					}
					if err = s.insert(tx, ev); err != nil {
						return err
					}
				}
			case *EventDeleteTask:
				if err = s.deleteAll(tx, t.pes); err != nil {
					return err
				}
			default:
				// Fallback or error
				taskErrors[i] = fmt.Errorf("unsupported task type for batching: %T", t)
			}
		}
		return nil
	})

	// Notify all tasks of the result
	for i, task := range tasks {
		if err != nil {
			// Transaction failed (e.g. disk issue), fail all
			task.Done(err)
		} else {
			// Transaction succeeded, return specific task error (e.g. duplication) or nil
			task.Done(taskErrors[i])
		}
	}
}

func (s *EventStore) handleTasks() {
	batch := make([]Task, 0, s.batchSize)

	// timer arms on the batch's first task, not a fixed schedule from
	// startup, so a solo write waits batchInterval from its own arrival, not
	// an arbitrary clock. A fixed-period ticker would instead make a
	// synchronous caller (waiting on each ack before its next write, a
	// common case) consistently land just after each tick and pay a full
	// extra period, instead of the average half-period random arrival gives.
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()

	flush := func() {
		if len(batch) > 0 {
			s.ExecuteBatch(batch)
			// Reset batch (reallocate to avoid keeping references, or slice)
			batch = make([]Task, 0, s.batchSize)
		}
		if timer != nil {
			timer.Stop()
			timer = nil
		}
	}

	for {
		var timerC <-chan time.Time
		if timer != nil {
			timerC = timer.C
		}

		select {
		case <-s.closeCh:
			flush() // flush whatever this goroutine had already dequeued

			// Drain and reject anything still sitting in taskQueue.
			// Execute checks closeCh before it ever offers a task to
			// taskQueue, so this is closing a narrow TOCTOU window, not the
			// common case -- but without it, a task that landed in the
			// channel in that window would never get a Done() call from
			// anyone, hanging its caller (e.g. writeOne) forever.
			for {
				select {
				case task := <-s.taskQueue:
					if task != nil {
						task.Done(ErrStoreClosed)
					}
				default:
					return
				}
			}

		case <-timerC:
			flush()

		case task := <-s.taskQueue:
			if task == nil {
				continue
			}
			batch = append(batch, task)
			if timer == nil {
				timer = time.NewTimer(s.batchInterval)
			}
			if len(batch) >= s.batchSize {
				flush()
			}
		}
	}
}

func (s *EventStore) startWorkers() {
	s.workersWg.Add(s.workers + 1) // +1 for startHousekeeper below
	for i := 0; i < s.workers; i++ {
		go func() {
			defer s.workersWg.Done()
			s.handleTasks()
		}()
	}
	go func() {
		defer s.workersWg.Done()
		s.startHousekeeper()
	}()
}

func (s *EventStore) insert(tx *bolt.Tx, ev *nip01.Event) error {
	switch {

	case nip09.IsDeletionKind(ev.Kind):
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
		defer cancel()
		pes, allowedKinds, err := s.findEventsToDelete(ctx, tx, ev.Tags, ev.CreatedAt)
		if err != nil {
			return err
		}
		if err := s.deleteAllRestricted(tx, ev, pes, allowedKinds); err != nil {
			return err
		}
		if _, err := s.insertEvent(tx, ev); err != nil && !errors.Is(err, ErrEventDuplicated) {
			return err
		}

	case nip16.IsEphemeralKind(ev.Kind):
		if err := s.insertWithIndexes(tx, ev); err != nil {
			return err
		}

	case nip33.IsParamReplaceableKind(ev.Kind):
		dValue := findFirstDtagValue(ev.Tags)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
		defer cancel()
		pes, err := s.findParameterizedReplaceableEvents(ctx, tx, ev.PubKey, ev.Kind, dValue, 0, 0)
		if err != nil {
			return err
		}

		if err := s.insertReplaceableEvent(tx, ev, pes); err != nil {
			return err
		}

	case nip16.IsReplaceableKind(ev.Kind):
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*20)
		defer cancel()
		pes, err := s.findReplaceableEvents(ctx, tx, ev.PubKey, ev.Kind, 0, 0)
		if err != nil {
			return err
		}

		if err := s.insertReplaceableEvent(tx, ev, pes); err != nil {
			return err
		}

	default:
		// case (ev.Kind >= 1_000 && ev.Kind < 10_000) || (ev.Kind >= 4 && ev.Kind < 45) || ev.Kind == 1 || ev.Kind == 2:
		if err := s.insertWithIndexes(tx, ev); err != nil {
			return err
		}

	}

	return nil

}

func (s *EventStore) checkEventDuplication(tx *bolt.Tx, ev *nip01.Event) error {
	eventIDBytes, err := hex.DecodeString(ev.ID)
	if err != nil {
		return err
	}

	c := tx.Bucket(indexID).Cursor()

	c.Seek(makeKey(eventIDBytes, maxUint64Bytes))
	k, _ := c.Prev()
	if k != nil && bytes.HasPrefix(k, eventIDBytes) {
		return ErrEventDuplicated
	}

	return nil
}

func (s *EventStore) insertReplaceableEvent(tx *bolt.Tx, ev *nip01.Event, pes []*PotentialEvent) error {
	if len(pes) == 0 {
		return s.insertWithIndexes(tx, ev)
	}

	latestPE, toDelete := s.determineLatestAndToDelete(pes)

	if err := s.deleteAll(tx, toDelete); err != nil {
		return err
	}

	if err := s.insertOrReplaceEvent(tx, ev, latestPE); err != nil {
		return err
	}

	return nil
}

func (s *EventStore) determineLatestAndToDelete(pes []*PotentialEvent) (*PotentialEvent, []*PotentialEvent) {

	if len(pes) == 1 {
		return pes[0], []*PotentialEvent{}
	}

	latestPE := pes[0]
	var toDelete []*PotentialEvent

	for i := 1; i < len(pes); i++ {
		if pes[i].CreatedAt > latestPE.CreatedAt {
			toDelete = append(toDelete, latestPE)
			latestPE = pes[i]
		} else if pes[i].CreatedAt == latestPE.CreatedAt {
			isLess, err := compareKeys(pes[i].EventID, latestPE.EventID)
			if err != nil {
				return latestPE, toDelete
			}
			if isLess {
				toDelete = append(toDelete, latestPE)
				latestPE = pes[i]
			} else {
				toDelete = append(toDelete, pes[i])
			}
		} else {
			toDelete = append(toDelete, pes[i])
		}
	}

	return latestPE, toDelete
}

func (s *EventStore) deleteAll(tx *bolt.Tx, pes []*PotentialEvent) error {
	for _, pe := range pes {
		if err := s.deleteByEvsid(tx, pe); err != nil {
			return err
		}
	}
	return nil
}

func (s *EventStore) deleteAllRestricted(tx *bolt.Tx, delEvent *nip01.Event, pes []*PotentialEvent, allowedKinds map[int]bool) error {

	for _, pe := range pes {
		event, err := s.findEventUsingTx(tx, pe.Evsid)
		if err != nil {
			if errors.Is(err, ErrEventNotFound) {
				continue // Event usage/body consistency broken, skip it
			}
			return err
		}

		if len(allowedKinds) > 0 {
			if _, ok := allowedKinds[event.Kind]; !ok {
				continue
			}
		}

		if delEvent.PubKey != event.PubKey {
			continue
		}

		if err := s.delete(tx, pe.Evsid, event); err != nil {
			return err
		}
	}
	return nil
}

func (s *EventStore) insertOrReplaceEvent(tx *bolt.Tx, ev *nip01.Event, latestPE *PotentialEvent) error {
	if ev.CreatedAt > latestPE.CreatedAt {
		if err := s.deleteByEvsid(tx, latestPE); err != nil {
			return err
		}
		if err := s.insertWithIndexes(tx, ev); err != nil {
			return err
		}
	} else if ev.CreatedAt == latestPE.CreatedAt {
		isLess, err := compareKeys(ev.ID, latestPE.EventID)
		if err != nil {
			return err
		}
		if isLess {
			if err := s.deleteByEvsid(tx, latestPE); err != nil {
				return err
			}
			if err := s.insertWithIndexes(tx, ev); err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *EventStore) deleteByEvsid(tx *bolt.Tx, pe *PotentialEvent) error {
	event, err := s.findEventUsingTx(tx, pe.Evsid)
	if err != nil {
		if errors.Is(err, ErrEventNotFound) {
			return nil // Already deleted (or inconsistent), proceed
		}
		return err
	}

	if err := s.delete(tx, pe.Evsid, event); err != nil {
		return err
	}

	return nil
}
func (s *EventStore) delete(tx *bolt.Tx, evsid uint64, ev *nip01.Event) error { // pass Event instead of PotentialEvent to optimize the delete process

	eventIDBytes, _ := hex.DecodeString(ev.ID)
	pubkeyBytes, _ := hex.DecodeString(ev.PubKey)
	evsidBytes := itob(evsid)
	kindBytes := itob(uint64(ev.Kind))

	tx.Bucket(indexEvents).Delete(evsidBytes)
	tx.Bucket(indexID).Delete(makeKey(eventIDBytes, evsidBytes))

	tx.Bucket(indexPubkey).Delete(makeKey(pubkeyBytes, evsidBytes))
	tx.Bucket(indexKind).Delete(makeKey(kindBytes, evsidBytes))
	tx.Bucket(indexKindPubkey).Delete(makeKey(kindBytes, pubkeyBytes, evsidBytes))

	// createdAt: 8+32+8
	createdAtKey := make([]byte, 0, 8+32+8)
	createdAtKey = append(createdAtKey, itob(ev.CreatedAt)...)
	createdAtKey = append(createdAtKey, eventIDBytes...)
	createdAtKey = append(createdAtKey, evsidBytes...)
	tx.Bucket(indexCreatedAt).Delete(createdAtKey)

	if exp, _ := getExpiration(ev.Tags); exp > 0 {
		expBytes := itob(exp)
		tx.Bucket(indexExpiration).Delete(makeKey(expBytes, evsidBytes))
	}

	tagEntries, err := prepareIndexableTags(ev.Tags, s.limitation.MaxIndexableTags)
	if err != nil {
		return err
	}
	for _, entry := range tagEntries {
		tx.Bucket(indexTag).Delete(makeKey(entry, evsidBytes))
	}

	return nil
}

func (s *EventStore) insertEvent(tx *bolt.Tx, event *nip01.Event) (uint64, error) {

	// events
	evBuckets := tx.Bucket(indexEvents)
	evsid, err := evBuckets.NextSequence()
	if err != nil {
		return 0, err
	}

	evsidBytes := itob(evsid)
	eventSerialized, err := json.Marshal(event)
	if err != nil {
		return 0, err
	}

	if err := evBuckets.Put(evsidBytes, eventSerialized); err != nil {
		return 0, err
	}

	return evsid, nil
}

func (s *EventStore) insertWithIndexes(tx *bolt.Tx, event *nip01.Event) error {

	evsid, err := s.insertEvent(tx, event)
	if err != nil {
		return err
	}

	return s.insertIndexes(tx, event, evsid)
}

func (s *EventStore) insertIndexes(tx *bolt.Tx, event *nip01.Event, evsid uint64) error {

	pubkeyBytes, err := hex.DecodeString(event.PubKey)
	if err != nil {
		return err
	}
	eventIDBytes, err := hex.DecodeString(event.ID)
	if err != nil {
		return err
	}
	evsidBytes := itob(evsid)
	createdAtBytes := itob(event.CreatedAt)
	kindBytes := itob(uint64(event.Kind))

	// id: 32+8
	if err := tx.Bucket(indexID).Put(makeKey(eventIDBytes, evsidBytes), createdAtBytes); err != nil {
		return err
	}

	// pubkey: 32+8
	if err := tx.Bucket(indexPubkey).Put(makeKey(pubkeyBytes, evsidBytes), createdAtBytes); err != nil {
		return err
	}

	// kind: 8+8
	if err := tx.Bucket(indexKind).Put(makeKey(kindBytes, evsidBytes), createdAtBytes); err != nil {
		return err
	}

	// tags
	tagEntries, err := prepareIndexableTags(event.Tags, s.limitation.MaxIndexableTags)
	if err != nil {
		return err
	}
	tagBucket := tx.Bucket(indexTag)
	for _, entry := range tagEntries {
		if err := tagBucket.Put(makeKey(entry, evsidBytes), createdAtBytes); err != nil {
			return err
		}
	}

	// createdAt: 8+32+8 -> value: 8 (timestamp)
	// We optimize this index for NIP-77 and general time-based sorting
	createdAtKey := make([]byte, 0, 8+32+8)
	createdAtKey = append(createdAtKey, createdAtBytes...)
	createdAtKey = append(createdAtKey, eventIDBytes...)
	createdAtKey = append(createdAtKey, evsidBytes...)

	if err := tx.Bucket(indexCreatedAt).Put(createdAtKey, createdAtBytes); err != nil {
		return err
	}

	// kind_pubkey: 8+32+8
	if err := tx.Bucket(indexKindPubkey).Put(makeKey(kindBytes, pubkeyBytes, evsidBytes), createdAtBytes); err != nil {
		return err
	}

	// expiration: 8+8
	exp, _ := getExpiration(event.Tags)
	if exp == 0 && nip16.IsEphemeralKind(event.Kind) {
		exp = uint64(event.CreatedAt + 600) // Default 10 minutes retention for ephemeral
	}

	if exp > 0 {
		expBytes := itob(exp)
		if err := tx.Bucket(indexExpiration).Put(makeKey(expBytes, evsidBytes), createdAtBytes); err != nil {
		}
	}

	if err := s.IndexZap(tx, event, evsid); err != nil {
		return err
	}

	return nil
}

func (s *EventStore) findEventUsingTx(tx *bolt.Tx, evsid uint64) (*nip01.Event, error) {

	bytes := tx.Bucket(indexEvents).Get(itob(evsid))
	if bytes == nil {
		return nil, fmt.Errorf("%w, evsid=%d", ErrEventNotFound, evsid)
	}

	var event *nip01.Event
	if err := json.Unmarshal(bytes, &event); err != nil {
		return nil, err
	}

	return event, nil
}

func (s *EventStore) findEventEvsidByEventID(ctx context.Context, tx *bolt.Tx, eventsID []string) ([]*PotentialEvent, error) {

	cursors, err := createCursorsByID(eventsID)
	if err != nil {
		return nil, err
	}

	sc := &scanContext{
		index:       indexID,
		queueEvents: newEventQueue(),
		filter:      &nip01.SubscriptionFilter{},
		sentEvents:  map[uint64]bool{},
	}

	for _, c := range cursors {
		if _, _, err := c.Collect(ctx, tx, sc, nil, len(eventsID), false); err != nil {
			return nil, err
		}
	}

	return sc.queueEvents.events, nil
}

func (s *EventStore) findReplaceableEvents(ctx context.Context, tx *bolt.Tx, pubKey string, kind int, since, until uint64) ([]*PotentialEvent, error) {
	return s.findEvents(ctx, tx, &nip01.SubscriptionFilter{
		Kinds:   []int{kind},
		Authors: []string{pubKey},
		Since:   since,
		Until:   until,
		Limit:   500,
	})
}

func (s *EventStore) findParameterizedReplaceableEvents(ctx context.Context, tx *bolt.Tx, pubKey string, kind int, dValue string, since, until uint64) ([]*PotentialEvent, error) {
	tags := map[string][]string{}
	tags["d"] = []string{dValue}

	return s.findEvents(ctx, tx, &nip01.SubscriptionFilter{
		Kinds:   []int{kind},
		Authors: []string{pubKey},
		Tags:    tags,
		Since:   since,
		Until:   until,
		Limit:   500,
	})
}

func (s *EventStore) findEventsToDelete(ctx context.Context, tx *bolt.Tx, tags [][]string, until uint64) ([]*PotentialEvent, map[int]bool, error) {

	var eventsToDelete []*PotentialEvent
	var eventsID []string
	requestedKinds := make(map[int]bool, len(tags))

	for _, tag := range tags {
		if len(tag) < 2 || len(tag[0]) != 1 {
			continue
		}

		switch tag[0] {
		case "k":
			kind, err := utils.ValidateStrKind(tag[1])
			if err != nil {
				continue
			}
			requestedKinds[kind] = true

		case "e":
			if err := utils.Validate32Key(tag[1]); err != nil {
				continue
			}
			eventsID = append(eventsID, tag[1])

		case "a":
			kind, pubKey, dValue, err := utils.ParseATag(tag[1])
			if err != nil {
				continue
			}

			switch {

			case nip16.IsReplaceableKind(kind):
				pes, err := s.findReplaceableEvents(ctx, tx, pubKey, kind, 0, until)
				if err != nil {
					return nil, nil, err
				}
				requestedKinds[kind] = true
				eventsToDelete = append(eventsToDelete, pes...)

			case nip33.IsParamReplaceableKind(kind):
				pes, err := s.findParameterizedReplaceableEvents(ctx, tx, pubKey, kind, dValue, 0, until)
				if err != nil {
					return nil, nil, err
				}
				requestedKinds[kind] = true
				eventsToDelete = append(eventsToDelete, pes...)
			}

		}
	}

	pes, err := s.findEventEvsidByEventID(ctx, tx, eventsID)
	if err != nil {
		return nil, nil, err
	}

	eventsToDelete = append(eventsToDelete, pes...)

	delete(requestedKinds, 5) // skip the deletion request of a deletion request

	return eventsToDelete, requestedKinds, nil
}

func (s *EventStore) findEventsByPubKeyAndKind(tx *bolt.Tx, event *nip01.Event) ([]*PotentialEvent, error) { // find events with same pubkey and kind
	filter := &nip01.SubscriptionFilter{
		Authors: []string{event.PubKey},
		Kinds:   []int{event.Kind},
	}
	return s.findEvents(context.Background(), tx, filter)
}

func (s *EventStore) FindEvents(ctx context.Context, filter *nip01.SubscriptionFilter) ([]*PotentialEvent, error) {
	return s.findEvents(ctx, nil, filter)
}

func (s *EventStore) findEvents(ctx context.Context, tx *bolt.Tx, filter *nip01.SubscriptionFilter) ([]*PotentialEvent, error) {

	filters := nip01.NewSubscriptionFilterGroup()
	filters.Add(filter)
	scan, err := NewStoreQuery(s, filters)
	if err != nil {
		return nil, err
	}

	potEvents := []*PotentialEvent{}
	potEventsCh := make(chan *PotentialEvent)
	var wg sync.WaitGroup
	go func() {
		for pv := range potEventsCh {
			potEvents = append(potEvents, pv)
			wg.Done()
		}
	}()
	if err := scan.fetch(ctx, tx, potEventsCh, &wg, true); err != nil {
		return nil, err
	}
	wg.Wait()
	close(potEventsCh)

	return potEvents, nil
}

func (s *EventStore) CountEvents(ctx context.Context, filters *nip01.SubscriptionFilterGroup) (int64, error) {
	scan, err := NewStoreQuery(s, filters)
	if err != nil {
		return 0, err
	}

	potEventsCh := make(chan *PotentialEvent)
	var wg sync.WaitGroup
	var count int64

	go func() {
		for range potEventsCh {
			count++
			wg.Done()
		}
	}()

	// Fetch trigger	// pass the transaction to scan.Fetch
	if err = scan.fetch(ctx, nil, potEventsCh, &wg, false); err != nil {
		return 0, err
	}
	wg.Wait()
	close(potEventsCh)

	return count, nil
}

func (s *EventStore) InsertEvents(ctx context.Context, events []*nip01.Event) error {

	task := NewEventInsertTask(events)
	s.Execute(ctx, task)

	select {
	case <-task.done:
	case err := <-task.errors:
		return err
	}

	return nil
}

func (s *EventStore) Execute(ctx context.Context, task Task) {
	// Checked before the select below (not just as one of its cases): once
	// closeCh is closed, this keeps a task from ever reaching taskQueue in
	// the first place, rather than relying on the racy alternative of a
	// select nondeterministically picking taskQueue <- task over <-closeCh
	// when both are simultaneously ready. handleTasks' own shutdown drain
	// (see its closeCh case) covers the remaining, narrower TOCTOU window
	// between this check and the send below.
	select {
	case <-s.closeCh:
		task.Done(ErrStoreClosed)
		return
	default:
	}

	select {
	case <-s.closeCh:
		task.Done(ErrStoreClosed)
	case <-ctx.Done():
		task.Done(ctx.Err())
	case s.taskQueue <- task:
	}
}

func (s *EventStore) FetchAll() ([]*nip01.Event, error) {

	events := []*nip01.Event{}

	if err := s.db.View(func(tx *bolt.Tx) error {

		b := tx.Bucket(indexEvents)
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			var eventObj *nip01.Event
			err := json.Unmarshal(v, &eventObj)
			if err != nil {
				return err
			}

			events = append(events, eventObj)
		}

		return nil
	}); err != nil {
		return nil, err
	}

	return events, nil
}

func (s *EventStore) FindEventBytes(evsid uint64) ([]byte, error) {

	var eventBytes []byte
	s.db.View(func(tx *bolt.Tx) error {
		eventBytes = tx.Bucket(indexEvents).Get(itob(evsid))
		return nil
	})

	if eventBytes == nil {
		return nil, fmt.Errorf("%w, evsid=%d", ErrEventNotFound, evsid)
	}

	return eventBytes, nil

}

func (s *EventStore) FindEvent(evsid uint64) (*nip01.Event, error) {

	bytes, err := s.FindEventBytes(evsid)
	if err != nil {
		return nil, err
	}

	var event *nip01.Event
	if err := json.Unmarshal(bytes, &event); err != nil {
		return nil, err
	}

	return event, nil
}

func (s *EventStore) DeleteAll(pes []*PotentialEvent) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return s.deleteAll(tx, pes)
	})
}

//////

type PotentialEvent struct {
	Evsid     uint64
	CreatedAt uint64
	EventID   string
}

type eventQueue struct {
	events []*PotentialEvent
}

func newEventQueue() *eventQueue {
	eq := &eventQueue{}
	heap.Init(eq)
	return eq
}

func (eq *eventQueue) Len() int { return len(eq.events) }

func (eq *eventQueue) Less(i, j int) bool {
	return eq.events[i].CreatedAt > eq.events[j].CreatedAt
}

func (eq *eventQueue) Swap(i, j int) {
	eq.events[i], eq.events[j] = eq.events[j], eq.events[i]
}

func (eq *eventQueue) Push(x interface{}) {
	eq.events = append(eq.events, x.(*PotentialEvent))
}

func (eq *eventQueue) Pop() interface{} {
	n := len(eq.events)
	event := eq.events[n-1]
	eq.events = eq.events[:n-1]
	return event
}

func (eq *eventQueue) PopEvent() *PotentialEvent {
	return heap.Pop(eq).(*PotentialEvent)
}

func (eq *eventQueue) AddEvent(ev *PotentialEvent) {
	heap.Push(eq, ev)
}

func (eq *eventQueue) Clear() {
	eq.events = eq.events[:0] // single thread
}

//////

type storeCursor struct {
	matchKey     func([]byte) bool
	parseKey     func([]byte) ([]byte, uint64, error)
	maxKey       []byte
	lastKey      []byte
	lastMaxEvsid uint64
	firstCollect bool
}

func newStoreCursor(maxKey []byte, matchKey func(k []byte) bool, parseKey func([]byte) ([]byte, uint64, error)) *storeCursor {
	return &storeCursor{
		matchKey: matchKey,
		parseKey: parseKey,
		maxKey:   maxKey,
	}
}

func (sc *storeCursor) SaveLastKey(key []byte) []byte {
	if !sc.firstCollect {
		return sc.lastKey
	}

	lastKey := sc.lastKey

	sc.lastKey = make([]byte, len(key))
	copy(sc.lastKey, key)

	sc.firstCollect = false
	return lastKey
}

func (sc *storeCursor) match(ss *scanContext, k, v []byte) (bool, error) {

	if !sc.matchKey(k) {
		return true, nil
	}

	idBytes, evsid, err := sc.parseKey(k)
	if err != nil {
		return true, err
	}

	if _, ok := ss.sentEvents[evsid]; ok {
		return false, nil
	}

	created := btoi(v)
	if (ss.filter.Since > 0 && created < ss.filter.Since) || (ss.filter.Until > 0 && created > ss.filter.Until) {
		return false, nil
	}

	var idHex string
	if len(idBytes) == 32 {
		idHex = hex.EncodeToString(idBytes)
	}

	ss.queueEvents.AddEvent(&PotentialEvent{evsid, created, idHex})
	ss.sentEvents[evsid] = true

	return false, nil
}

func (sc *storeCursor) Collect(ctx context.Context, tx *bolt.Tx, ss *scanContext, resumeKey []byte, limit int, fetchUntilEmpty bool) ([]byte, int, error) {

	b := tx.Bucket(ss.index)
	c := b.Cursor()

	var k, v []byte

	if resumeKey != nil {
		c.Seek(resumeKey)
		k, v = c.Prev()
	} else {
		c.Seek(sc.maxKey)
		k, v = c.Prev()
	}

	wasFirstCollect := sc.firstCollect
	lastKey := sc.SaveLastKey(k)

	// The lastKey boundary is a scan-efficiency optimization: it assumes newly
	// inserted entries always sort above previously seen ones, which holds for
	// indexes whose key ends in the monotonically increasing evsid (kind, pubkey,
	// id, tag, ...), so an early exit on raw key order is safe there. The
	// default/created_at index is keyed by timestamp first, and client-supplied
	// created_at values aren't guaranteed monotonic with insertion order, so a
	// newly inserted event can sort behind the boundary key. For that index,
	// snapshot the store-wide max evsid at the start of each fresh scan pass and
	// use it (instead of raw key/position order) to tell "old, already accounted
	// for" entries from newly inserted ones, scanning past out-of-order entries
	// rather than stopping early.
	isDefaultIndex := bytes.Equal(ss.index, indexCreatedAt)
	var boundaryEvsid uint64
	var hasBoundaryEvsid bool
	if isDefaultIndex {
		if wasFirstCollect {
			boundaryEvsid = sc.lastMaxEvsid
			hasBoundaryEvsid = boundaryEvsid > 0
			sc.lastMaxEvsid = tx.Bucket(indexEvents).Sequence()
		} else {
			boundaryEvsid = sc.lastMaxEvsid
			hasBoundaryEvsid = true
		}
	}

	var collected int

loop:
	for ; k != nil && (limit > 0 || fetchUntilEmpty); k, v = c.Prev() {

		select {
		case <-ctx.Done():
			break loop

		default:
			if fetchUntilEmpty && lastKey != nil {
				if isDefaultIndex {
					if hasBoundaryEvsid {
						if _, evsid, err := sc.parseKey(k); err == nil && evsid <= boundaryEvsid {
							continue
						}
					}
				} else if bytes.Compare(k, lastKey) <= 0 {
					break loop
				}
			}

			done, err := sc.match(ss, k, v)
			if err != nil {
				return nil, 0, err
			}
			if done {
				break loop
			}

			collected++
			resumeKey = k
			limit--
		}
	}

	return resumeKey, collected, nil
}

//////

type scanContext struct {
	index       []byte
	queueEvents *eventQueue
	filter      *nip01.SubscriptionFilter
	sentEvents  map[uint64]bool
}

type storeScan struct {
	store   *EventStore
	cursors []*storeCursor
	*scanContext
}

func newStoreScan(store *EventStore, filter *nip01.SubscriptionFilter, sentEvents map[uint64]bool) (*storeScan, error) {
	ss := &storeScan{
		store: store,
		scanContext: &scanContext{
			filter:      filter,
			queueEvents: newEventQueue(),
			sentEvents:  sentEvents,
		},
	}

	var err error

	switch {
	case len(filter.IDs) > 0:
		ss.index = indexID
		ss.cursors, err = createCursorsByID(filter.IDs)
	case len(filter.Tags) > 0:
		ss.index = indexTag
		ss.cursors, err = createCursorsByTags(filter.Tags)
	case len(filter.Authors) > 0 && len(filter.Kinds) > 0:
		ss.index = indexKindPubkey
		ss.cursors, err = createCursorsByKindsAndAuthors(filter.Kinds, filter.Authors)
	case len(filter.Authors) > 0:
		ss.index = indexPubkey
		ss.cursors, err = createCursorsByAuthors(filter.Authors)
	case len(filter.Kinds) > 0:
		ss.index = indexKind
		ss.cursors, err = createCursorsByKinds(filter.Kinds)
	default:
		ss.index = indexCreatedAt
		ss.cursors = append(ss.cursors, defaultCursor())
	}

	if err != nil {
		return nil, err
	}

	return ss, nil
}

func (ss *storeScan) initializeScan() (map[int][]byte, int, int) {
	resumeKeys := make(map[int][]byte, len(ss.cursors))
	limit := int(math.Ceil(float64(ss.filter.Limit) / float64(len(ss.cursors))))
	for ci := range ss.cursors {
		ss.cursors[ci].firstCollect = true
	}
	return resumeKeys, limit, 5
}

func (ss *storeScan) Scan(ctx context.Context, potEvents chan<- *PotentialEvent, wg *sync.WaitGroup, fetchUntilEmpty bool) error {
	return ss.scan(ctx, nil, potEvents, wg, fetchUntilEmpty)
}

func (ss *storeScan) scan(ctx context.Context, tx *bolt.Tx, potEvents chan<- *PotentialEvent, wg *sync.WaitGroup, fetchUntilEmpty bool) error {
	if len(ss.cursors) == 0 {
		return nil
	}

	runScan := func(tx *bolt.Tx) error {

		resumeKeys, limit, refill := ss.initializeScan()

		var totalCollected int
		activeCursors := true

		for activeCursors {

			cursorLimit := limit * refill
			activeCursors = false

			for ci, cursor := range ss.cursors {

				select {
				case <-ss.store.closeCh:
					return nil

				case <-ctx.Done():
					return ctx.Err()

				default:

					if !fetchUntilEmpty && cursorLimit > ss.filter.Limit-totalCollected {
						cursorLimit = ss.filter.Limit - totalCollected
					}

					var collected int
					var err error
					resumeKeys[ci], collected, err = cursor.Collect(ctx, tx, ss.scanContext, resumeKeys[ci], cursorLimit, fetchUntilEmpty)
					if err != nil {
						return err
					}

					if collected > 0 {

						sent, err := ss.handleEvents(ctx, potEvents, tx, wg, fetchUntilEmpty)
						if err != nil {
							return err
						}

						totalCollected += sent
						activeCursors = collected == cursorLimit
					}

					if !fetchUntilEmpty && totalCollected >= ss.filter.Limit {
						activeCursors = false
					}

				}

			}

			refill = 10
		}

		return nil
	}

	if tx != nil {
		return runScan(tx)
	}

	err := ss.store.db.View(func(tx *bolt.Tx) error {
		return runScan(tx)
	})

	return err
}

func (s *EventStore) QueryNip77Items(ctx context.Context, filter *nip01.SubscriptionFilter) ([]nip77.Item, error) {
	fg := nip01.NewSubscriptionFilterGroup()
	fg.Add(filter)

	q, err := NewStoreQuery(s, fg)
	if err != nil {
		return nil, err
	}

	outgoing := make(chan *PotentialEvent, 500)
	var wg sync.WaitGroup

	// Collect items
	items := make([]nip77.Item, 0)

	// Async fetch
	go func() {
		q.Fetch(ctx, outgoing, &wg, false)
		wg.Wait()
		close(outgoing)
	}()

	for pe := range outgoing {
		func() {
			defer wg.Done()
			idBytes, err := hex.DecodeString(pe.EventID)
			if err != nil || len(idBytes) != 32 {
				return
			}
			var id [32]byte
			copy(id[:], idBytes)

			items = append(items, nip77.Item{
				Timestamp: pe.CreatedAt,
				ID:        id,
			})
		}()
	}

	return items, nil
}

func (ss *storeScan) handleEvents(ctx context.Context, potEvents chan<- *PotentialEvent, tx *bolt.Tx, wg *sync.WaitGroup, fetchUntilEmpty bool) (int, error) {

	var sent int
	for ss.queueEvents.Len() > 0 {

		potEvent := ss.queueEvents.PopEvent()
		event, err := ss.store.findEventUsingTx(tx, potEvent.Evsid)
		if err != nil {
			return sent, err
		}

		// NIP-16: Ephemeral events should not be sent for historical requests
		if !fetchUntilEmpty && nip16.IsEphemeralKind(event.Kind) {
			continue
		}

		if !ss.filter.Match(event) {
			continue
		}

		wg.Add(1)

		potEvent.EventID = event.ID

		select {
		case potEvents <- potEvent:
		case <-ctx.Done():
			wg.Done()
			return sent, ctx.Err()
		}
		sent++
	}

	return sent, nil
}

//////

type StoreQuery struct {
	filters    *nip01.SubscriptionFilterGroup
	sentEvents map[uint64]bool
	scanners   []*storeScan
	queryLimit int
}

func NewStoreQuery(store *EventStore, filters *nip01.SubscriptionFilterGroup) (*StoreQuery, error) {

	sq := &StoreQuery{
		filters:    filters,
		sentEvents: make(map[uint64]bool),
		scanners:   []*storeScan{},
	}

	for _, filter := range filters.GetAll() {
		filter.Limit = clamp(filter.Limit, filterMinLimit, store.limitation.MaxLimit)
		if ss, err := newStoreScan(store, filter, sq.sentEvents); err != nil {
			return nil, err
		} else {
			sq.scanners = append(sq.scanners, ss)
			sq.queryLimit += filter.Limit
		}
	}

	return sq, nil
}

func (q *StoreQuery) Fetch(ctx context.Context, out chan<- *PotentialEvent, wg *sync.WaitGroup, keepOpen bool) error {
	return q.fetch(ctx, nil, out, wg, keepOpen)
}

func (q *StoreQuery) fetch(ctx context.Context, tx *bolt.Tx, out chan<- *PotentialEvent, wg *sync.WaitGroup, keepOpen bool) error {

	// We have multiple scanners (one per filter)
	// We want to fetch events from all scanners and merge them
	// We also want to apply the limit across all scanners? No, limit is per filter.
	// But duplicate removal is across all scanners (handled by sentEvents map which is shared).

	for _, s := range q.scanners {
		// pass tx to s.scan
		if err := s.scan(ctx, tx, out, wg, keepOpen); err != nil {
			return err
		}
	}
	return nil
}

//////

func prepareIndexableTags(tags [][]string, maxIndexableTags int) ([][]byte, error) {

	var entries [][]byte

	for _, tagSet := range tags {

		if len(tagSet) < 2 {
			continue
		}

		tagName := tagSet[0]
		tagFirstVal := tagSet[1]

		if err := utils.ValidateIndexableTag(tagName); err != nil {
			continue
		}

		entries = append(entries, []byte(tagName+tagFirstVal))

		if len(entries) == maxIndexableTags {
			break
		}
	}

	return entries, nil
}

func itob(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func btoi(b []byte) uint64 {
	if len(b) < 8 {
		panic("byte slice is too short to convert to int")
	}
	return binary.BigEndian.Uint64(b)
}

func makeKey(key []byte, vals ...[]byte) []byte {
	for _, val := range vals {
		key = append(key, val...)
	}
	return key
}

func clamp(value, min, max int) int {
	if value == 0 {
		return max
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}

func compareKeys(id1, id2 string) (bool, error) {
	bytes1, err := hex.DecodeString(id1)
	if err != nil {
		return false, err
	}

	bytes2, err := hex.DecodeString(id2)
	if err != nil {
		return false, err
	}

	return bytes.Compare(bytes1, bytes2) < 0, nil
}

func findFirstDtagValue(tags [][]string) string {
	if len(tags) == 0 {
		return ""
	}

	for _, t := range tags {
		if len(t) == 1 {
			continue
		}
		if t[0] == "d" || t[0] == "D" {
			return t[1]
		}
	}

	return ""
}

// Helper to handle creation of cursors by ID
func createCursorsByID(ids []string) ([]*storeCursor, error) {
	var cursors []*storeCursor
	for _, eid := range ids {
		prefix, err := hex.DecodeString(eid)
		if err != nil {
			return nil, err
		}
		if len(prefix) != 32 {
			return nil, fmt.Errorf("bad eid size")
		}
		cursors = append(cursors, newStoreCursor(
			makeKey(prefix, maxUint64Bytes),
			func(k []byte) bool {
				return bytes.HasPrefix(k, prefix)
			},
			func(k []byte) ([]byte, uint64, error) {
				if len(k) != 32+8 {
					return nil, 0, fmt.Errorf("id cursor: bad key size got=%d", len(k))
				}
				return nil, btoi(k[32:]), nil
			},
		))
	}
	return cursors, nil
}

// Helper to handle creation of cursors by tags
func createCursorsByTags(tags map[string][]string) ([]*storeCursor, error) {
	var cursors []*storeCursor
	for tagName, tagValues := range tags {
		for _, tagVal := range tagValues {
			prefix := []byte(tagName + tagVal)
			cursors = append(cursors, newStoreCursor(
				makeKey(prefix, maxUint64Bytes),
				func(k []byte) bool {
					// tag's value must be size fixed. reminder : ["h", "1"] && ["h", "10"]
					// check test case: case_tags_5
					return len(k) == len(prefix)+8 && bytes.HasPrefix(k, prefix)
				},
				func(k []byte) ([]byte, uint64, error) {
					if len(k) != len(prefix)+8 {
						return nil, 0, fmt.Errorf("tag cursor: bad key size got=%d", len(k))
					}
					return nil, btoi(k[len(k)-8:]), nil
				},
			))
		}
	}
	return cursors, nil
}

// Helper to handle creation of cursors by authors
func createCursorsByAuthors(authors []string) ([]*storeCursor, error) {
	var cursors []*storeCursor
	for _, pubKey := range authors {
		prefix, err := hex.DecodeString(pubKey)
		if err != nil {
			return nil, err
		}
		if len(prefix) != 32 {
			return nil, fmt.Errorf("bad pubkey size")
		}
		cursors = append(cursors, newStoreCursor(
			makeKey(prefix, maxUint64Bytes),
			func(k []byte) bool {
				return bytes.HasPrefix(k, prefix)
			},
			func(k []byte) ([]byte, uint64, error) {
				if len(k) != 32+8 {
					return nil, 0, fmt.Errorf("pubkey cursor: bad key size got=%d", len(k))
				}
				return nil, btoi(k[32:]), nil
			},
		))
	}
	return cursors, nil
}

// Helper to handle creation of cursors by kinds
func createCursorsByKinds(kinds []int) ([]*storeCursor, error) {
	var cursors []*storeCursor
	for _, kind := range kinds {
		prefix := itob(uint64(kind))
		cursors = append(cursors, newStoreCursor(
			makeKey(prefix, maxUint64Bytes),
			func(k []byte) bool {
				return bytes.HasPrefix(k, prefix)
			},
			func(k []byte) ([]byte, uint64, error) {
				if len(k) != 8+8 {
					return nil, 0, fmt.Errorf("kind cursor: bad key size got=%d", len(k))
				}
				return nil, btoi(k[8:]), nil
			},
		))
	}
	return cursors, nil
}

// Helper to handle creation of cursors by kinds and authors (combined)
func createCursorsByKindsAndAuthors(kinds []int, authors []string) ([]*storeCursor, error) {
	var cursors []*storeCursor
	for _, kind := range kinds {
		prefixKind := itob(uint64(kind))
		for _, pubKey := range authors {
			pubKeyBytes, err := hex.DecodeString(pubKey)
			if err != nil {
				return nil, err
			}
			if len(pubKeyBytes) != 32 {
				return nil, fmt.Errorf("bad pubkey size")
			}
			prefix := append(prefixKind, pubKeyBytes...)
			cursors = append(cursors, newStoreCursor(
				makeKey(prefix, maxUint64Bytes),
				func(k []byte) bool {
					return bytes.HasPrefix(k, prefix)
				},
				func(k []byte) ([]byte, uint64, error) {
					if len(k) != 8+32+8 {
						return nil, 0, fmt.Errorf("kind,pubkeys cursor: bad key size got=%d", len(k))
					}
					return nil, btoi(k[40:]), nil
				},
			))
		}
	}
	return cursors, nil
}

func defaultCursor() *storeCursor {
	return newStoreCursor(
		makeKey(maxUint64Bytes),
		func(k []byte) bool {
			return true
		},
		func(k []byte) ([]byte, uint64, error) {
			if len(k) != 48 {
				return nil, 0, fmt.Errorf("default cursor: bad key size got=%d", len(k))
			}
			// Key: Timestamp(8) + ID(32) + evsid(8)
			// Return ID (32 bytes) as first arg, evsid as second
			idBytes := make([]byte, 32)
			copy(idBytes, k[8:40])
			return idBytes, btoi(k[40:]), nil
		},
	)
}

func (s *EventStore) startHousekeeper() {
	ticker := time.NewTicker(time.Minute * 10)
	defer ticker.Stop()

	for {
		select {
		case <-s.closeCh:
			return
		case <-ticker.C:
			s.pruneExpiredEvents()
		}
	}
}

func (s *EventStore) pruneExpiredEvents() error {
	now := time.Now().Unix()
	nowBytes := itob(uint64(now))

	var peToDelete []*PotentialEvent

	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(indexExpiration).Cursor()

		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			if len(k) != 16 {

				continue
			}
			expPart := k[:8]
			if bytes.Compare(expPart, nowBytes) > 0 {
				break
			}

			evsid := btoi(k[8:])
			peToDelete = append(peToDelete, &PotentialEvent{Evsid: evsid})
		}
		return nil
	})
	if err != nil {
		return err
	}

	if len(peToDelete) > 0 {
		task := NewEventDeleteTask(peToDelete)
		s.Execute(context.Background(), task)
	}

	return nil
}

func getExpiration(tags [][]string) (uint64, error) {
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == "expiration" {
			return strconv.ParseUint(tag[1], 10, 64)
		}
	}
	return 0, nil
}
