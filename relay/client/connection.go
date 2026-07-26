// Package client is a Nostr relay WebSocket client: dial a relay
// (Connection), publish and subscribe, and round-trip higher-level
// protocols built on top of the wire format (e.g. NWCClient for NIP-47).
// It wraps the wire and nip01 packages so callers don't need to handle raw
// relay packets directly.
package client

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/wire"
)

const (
	wsReadBuffer       = 1024
	wsWriteBuffer      = 1024
	wsHandshakeTimeout = 5 * time.Second

	wsPingInterval     = 30 * time.Second
	wsPingWriteTimeout = 15 * time.Second
	wsPongTimeout      = 60 * time.Second
	wsDataWriteTimeout = 60 * time.Second

	incomingEventBufferSize = 10240
)

var (
	wsBufferPool        = new(sync.Pool)
	ErrConnectionClosed = errors.New("connection closed")
)

type ConnectionError struct {
	Relay   *url.URL
	Message string
	Origin  error
}

func (ce *ConnectionError) Error() string {
	if ce.Origin != nil {
		return fmt.Sprintf("%s: %s: %v", ce.Relay, ce.Message, ce.Origin)
	} else {
		return fmt.Sprintf("%s: %s", ce.Relay, ce.Message)
	}
}

func (ce *ConnectionError) Unwrap() error {
	return ce.Origin
}

func NewConnectionError(relay *url.URL, message string, err error) error {
	return &ConnectionError{relay, message, err}
}

type ConnectionConfig struct {
	HandshakeTimeout time.Duration
	PingInterval     time.Duration
	PongTimeout      time.Duration
	WriteTimeout     time.Duration
}

func DefaultConnectionConfig() *ConnectionConfig {
	return &ConnectionConfig{
		HandshakeTimeout: wsHandshakeTimeout,
		PingInterval:     wsPingInterval,
		PongTimeout:      wsPongTimeout,
		WriteTimeout:     wsDataWriteTimeout,
	}
}

// subDispatch is the per-subscription fan-out target registered by
// Subscribe. The read loop in handle() forwards every EVENT/EOSE/CLOSED
// message to both the shared incoming channel (for Read()/Events()) and,
// if its SubscriptionID matches an entry here, to that subscription's own
// typed channel — this is a broadcast, not a competing consumer, so
// registering a subscription never steals messages away from Read().
type subDispatch struct {
	events chan *wire.EventSubscriptionResponse
	done   chan struct{}
}

type Connection struct {
	relay    *url.URL
	outgoing chan interface{}
	incoming chan wire.SubscriptionResponse
	errors   chan error

	closeCh chan interface{}
	closer  sync.Once

	conn    *websocket.Conn
	writeMu sync.Mutex

	config *ConnectionConfig

	subsMu sync.Mutex
	subs   map[string]*subDispatch
}

// Connect dials relayURL with default timeouts and intervals. This is the
// common path — for custom handshake/ping/write timeouts, use NewConnection
// with an explicit *ConnectionConfig instead.
func Connect(ctx context.Context, relayURL *url.URL) (*Connection, error) {
	return NewConnection(ctx, relayURL, nil)
}

func NewConnection(ctx context.Context, relayURL *url.URL, cfg *ConnectionConfig) (*Connection, error) {
	if cfg == nil {
		cfg = DefaultConnectionConfig()
	}
	// fill missing defaults if partial config provided
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = wsHandshakeTimeout
	}
	if cfg.PingInterval == 0 {
		cfg.PingInterval = wsPingInterval
	}
	if cfg.PongTimeout == 0 {
		cfg.PongTimeout = wsPongTimeout
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = wsDataWriteTimeout
	}

	c := &Connection{
		relay:    relayURL,
		outgoing: make(chan interface{}),
		incoming: make(chan wire.SubscriptionResponse, incomingEventBufferSize),
		errors:   make(chan error),
		closeCh:  make(chan interface{}),
		config:   cfg,
		subs:     make(map[string]*subDispatch),
	}

	d := websocket.Dialer{
		ReadBufferSize:    wsReadBuffer,
		WriteBufferSize:   wsWriteBuffer,
		WriteBufferPool:   wsBufferPool,
		HandshakeTimeout:  cfg.HandshakeTimeout,
		EnableCompression: true,
	}

	var err error
	c.conn, _, err = d.Dial(relayURL.String(), nil)
	if err != nil {
		return nil, NewConnectionError(relayURL, "failed to connect", err)
	}

	c.conn.SetReadDeadline(time.Now().Add(cfg.PongTimeout))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(cfg.PongTimeout))
		return nil
	})

	go c.handle(ctx)
	go c.pingLoop()

	return c, nil
}

func (c *Connection) handle(parent context.Context) {

	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	go func() {
		defer c.Close()

		for {
			select {
			case p := <-c.outgoing:
				c.writeMu.Lock()
				c.conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout))

				if err := c.conn.WriteJSON(p); err != nil {
					c.writeMu.Unlock()
					select {
					case c.errors <- fmt.Errorf("write: %w", err):
					case <-c.closeCh:
					case <-ctx.Done():
					}
					return
				}
				c.writeMu.Unlock()

			case <-c.closeCh:
				return

			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		var p wire.ClientPayload
		if err := c.conn.ReadJSON(&p); err != nil {
			isPacketErr := wire.IsPacketError(err)
			switch {
			case isPacketErr:
				select {
				case c.errors <- err:
				case <-c.closeCh:
				case <-ctx.Done():
				}
			case websocket.IsCloseError(err,
				websocket.CloseAbnormalClosure,
				websocket.CloseNormalClosure,
				websocket.CloseGoingAway,
				websocket.CloseNoStatusReceived):
				select {
				case c.errors <- ErrConnectionClosed:
				case <-c.closeCh:
				case <-ctx.Done():
				}
				return
			default:
				select {
				case c.errors <- fmt.Errorf("read: %w", err):
				case <-c.closeCh:
				case <-ctx.Done():
				}
				return
			}
		} else {
			c.dispatch(p.SubscriptionResponse)
			select {
			case c.incoming <- p.SubscriptionResponse:
			case <-c.closeCh:
			case <-ctx.Done():
			}
		}
		c.conn.SetReadDeadline(time.Now().Add(c.config.PongTimeout))
	}

}

func (c *Connection) pingLoop() {

	ticker := time.NewTicker(c.config.PingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.closeCh:
			return
		case <-ticker.C:
			c.writeMu.Lock()
			c.conn.SetWriteDeadline(time.Now().Add(c.config.WriteTimeout))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				c.writeMu.Unlock()
				select {
				case c.errors <- fmt.Errorf("ping: %w", err):
				case <-c.closeCh:
				}
				return
			}
			c.writeMu.Unlock()
		}
	}
}

// Subscribe opens a subscription and returns its ID plus a typed channel of
// just this subscription's EVENT messages, closing both the events and done
// channels at EOSE, at CLOSED, or when the connection closes. This is the
// common path for "give me the events for this filter." For a long-lived
// subscription that must keep receiving events past EOSE, or for manual
// control over the subscription ID and access to every message
// type/subscription on the connection, use SubscribeWithID + Read instead —
// don't mix the two consumption styles on the same Connection concurrently.
func (c *Connection) Subscribe(filter *nip01.SubscriptionFilterGroup) (subID string, events <-chan *wire.EventSubscriptionResponse, done <-chan struct{}) {
	subID = uuid.NewString()
	sd := &subDispatch{
		events: make(chan *wire.EventSubscriptionResponse, incomingEventBufferSize),
		done:   make(chan struct{}),
	}

	c.subsMu.Lock()
	c.subs[subID] = sd
	c.subsMu.Unlock()

	if ok := c.SubscribeWithID(subID, filter); !ok {
		c.closeSub(subID)
	}

	return subID, sd.events, sd.done
}

func (c *Connection) SubscribeWithID(subID string, filter *nip01.SubscriptionFilterGroup) bool {

	select {
	case c.outgoing <- wire.NewRequestPacket(subID, filter):
		return true
	case <-c.closeCh:
		return false
	}
}

// dispatch fans a subscription-scoped message out to its registered
// subDispatch, if any, in addition to (not instead of) it being forwarded
// onto the shared incoming channel by the caller.
func (c *Connection) dispatch(res wire.SubscriptionResponse) {
	switch m := res.(type) {
	case *wire.EventSubscriptionResponse:
		c.subsMu.Lock()
		sd, ok := c.subs[m.SubscriptionID]
		c.subsMu.Unlock()
		if !ok {
			return
		}
		select {
		case sd.events <- m:
		case <-c.closeCh:
		}
	case *wire.EOSESubscriptionResponse:
		c.closeSub(m.SubscriptionID)
	case *wire.ClosedSubscriptionResponse:
		c.closeSub(m.SubscriptionID)
	}
}

// closeSub removes and closes a subscription's channels exactly once. Safe
// to call from both the normal EOSE/CLOSED dispatch path and Close()'s
// cleanup sweep, since both go through the same subsMu-guarded map.
func (c *Connection) closeSub(subID string) {
	c.subsMu.Lock()
	sd, ok := c.subs[subID]
	if ok {
		delete(c.subs, subID)
	}
	c.subsMu.Unlock()
	if ok {
		close(sd.events)
		close(sd.done)
	}
}

// Read returns the shared channel of every incoming message type for every
// subscription on this connection — the advanced, un-demultiplexed view.
// For the common case of "just the events for one subscription," use
// Subscribe or Events instead.
func (c *Connection) Read() <-chan wire.SubscriptionResponse {
	return c.incoming
}

// Events filters Read()'s shared channel down to EVENT messages for one
// subscription ID (or all, if subID is ""). Advanced: pairs with
// SubscribeWithID when you need to retain manual control of the
// subscription ID; for the common case, use Subscribe instead, which
// doesn't require also consuming Read() yourself.
func (c *Connection) Events(subID string) <-chan *wire.EventSubscriptionResponse {
	out := make(chan *wire.EventSubscriptionResponse, incomingEventBufferSize)
	go func() {
		defer close(out)
		for {
			select {
			case res, ok := <-c.incoming:
				if !ok {
					return
				}
				ev, isEvent := res.(*wire.EventSubscriptionResponse)
				if !isEvent || (subID != "" && ev.SubscriptionID != subID) {
					continue
				}
				select {
				case out <- ev:
				case <-c.closeCh:
					return
				}
			case <-c.closeCh:
				return
			}
		}
	}()
	return out
}

// Relay reports the URL this connection was dialed against.
func (c *Connection) Relay() *url.URL {
	return c.relay
}

func (c *Connection) Send(ev *nip01.Event) bool {
	select {
	case c.outgoing <- wire.NewEventPacket(ev):
		return true
	case <-c.closeCh:
		return false
	}
}

// Publish sends ev and blocks until the relay responds OK for this event's
// ID, ctx is cancelled, or the connection errors/closes. This is the common
// path for "did my event make it." For fire-and-forget with no acceptance
// confirmation, use Send. Publish consumes from the same shared channel as
// Read(), so don't run it concurrently with your own Read() loop on the
// same Connection.
func (c *Connection) Publish(ctx context.Context, ev *nip01.Event) (*wire.OkSubscriptionResponse, error) {
	if !c.Send(ev) {
		return nil, ErrConnectionClosed
	}
	for {
		select {
		case res, ok := <-c.incoming:
			if !ok {
				return nil, ErrConnectionClosed
			}
			if okResp, match := res.(*wire.OkSubscriptionResponse); match && okResp.EventID == ev.ID {
				return okResp, nil
			}
			// Not the response we're waiting for (a NOTICE, an unrelated
			// OK, another subscription's EVENT, etc.) — keep waiting.
		case err := <-c.errors:
			return nil, err
		case <-c.closeCh:
			return nil, ErrConnectionClosed
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (c *Connection) CloseSubscription(subID string) bool {
	select {
	case c.outgoing <- wire.NewClosePacket(subID):
		return true
	case <-c.closeCh:
		return false
	}
}

// Outgoing exposes the raw outgoing packet channel for packet types (e.g. NIP-77
// negentropy packets) that don't have a dedicated semantic method above.
func (c *Connection) Outgoing() chan<- interface{} {
	return c.outgoing
}

func (c *Connection) Close() {

	c.closer.Do(func() {
		close(c.closeCh)
		if c.conn != nil {
			c.conn.Close()
		}

		c.subsMu.Lock()
		subs := c.subs
		c.subs = make(map[string]*subDispatch)
		c.subsMu.Unlock()
		for _, sd := range subs {
			close(sd.events)
			close(sd.done)
		}
	})

}

func (c *Connection) Errors() <-chan error {
	return c.errors
}

func (c *Connection) Closed() <-chan interface{} {
	return c.closeCh
}
