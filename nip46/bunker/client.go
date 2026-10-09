package bunker

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"sync"

	btcec "github.com/flokiorg/go-flokicoin/crypto"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip46"
	relayclient "github.com/ohstr/nmilat/relay/client"
)

var _ nip46.Key = (*Client)(nil)

// ErrClosed means the Client was closed.
var ErrClosed = errors.New("bunker: client closed")

// ClientOptions configure Dial, Resume and NewPairing.
type ClientOptions struct {
	// ClientKey is the app's own key for the conversation, hex or nsec.
	// Empty generates a fresh one; Client.Session keeps it for Resume.
	ClientKey string
	// Perms is the permission list to ask for, e.g. "sign_event:1,nip44_encrypt".
	Perms string
	// Metadata describes the app to the signer.
	Metadata *nip46.Metadata
	// Encryption is the request scheme; empty means nip46.EncryptionNIP44V2.
	Encryption string
	// OnAuthURL is called when the signer asks the user to open a URL
	// before it answers (NIP-46 auth challenge). The call keeps waiting.
	OnAuthURL func(url string)
	// Logf receives relay connection messages.
	Logf func(format string, args ...any)
}

// Session is what Resume needs to reconnect to a paired signer without a
// new pairing secret. ClientKey is a private key: store it as one.
type Session struct {
	SignerPubKey string   `json:"signer_pubkey"`
	UserPubKey   string   `json:"user_pubkey"`
	Relays       []string `json:"relays"`
	ClientKey    string   `json:"client_key"`
}

// Client signs through a remote signer over relays. It is safe for
// concurrent use. Requests go to every connected relay; the first
// response wins.
type Client struct {
	opts       ClientOptions
	clientPriv string
	clientPub  string
	relays     []string
	pool       *pool
	stop       context.CancelFunc
	done       chan struct{}

	mu        sync.Mutex
	signerPub string
	userPub   string
	pending   map[string]chan *nip46.ResponseEvent
	closed    bool

	// nostrconnect:// pairing state
	pairSecret string
	paired     chan struct{}
}

func newClient(signerPub string, relays []string, opts ClientOptions) (*Client, error) {
	if opts.Encryption == "" {
		opts.Encryption = nip46.EncryptionNIP44V2
	}
	if opts.Encryption != nip46.EncryptionNIP04 && opts.Encryption != nip46.EncryptionNIP44V2 {
		return nil, fmt.Errorf("%w: %q", nip46.ErrUnsupportedEncryption, opts.Encryption)
	}
	clientKey := opts.ClientKey
	if clientKey == "" {
		k, err := btcec.NewPrivateKey()
		if err != nil {
			return nil, fmt.Errorf("bunker: generate client key: %w", err)
		}
		clientKey = hex.EncodeToString(k.Serialize())
	}
	lk, err := nip46.NewLocalKey(clientKey)
	if err != nil {
		return nil, fmt.Errorf("bunker: invalid ClientKey: %w", err)
	}
	var norm []string
	for _, r := range relays {
		n, err := normalizeRelay(r)
		if err != nil {
			continue
		}
		norm = append(norm, n)
	}
	if len(norm) == 0 {
		return nil, errors.New("bunker: no usable relay")
	}
	c := &Client{
		opts:       opts,
		clientPriv: lk.PrivKeyHex(),
		clientPub:  lk.PubKey(),
		relays:     norm,
		signerPub:  signerPub,
		pending:    map[string]chan *nip46.ResponseEvent{},
		done:       make(chan struct{}),
	}
	filter := nip01.NewSubscriptionFilterGroup(&nip01.SubscriptionFilter{
		Kinds: []int{nip46.KindRequest},
		Tags:  map[string][]string{"p": {c.clientPub}},
	})
	c.pool = newPool(filter, c.onEvent, opts.Logf)
	return c, nil
}

// start serves the relays until Close.
func (c *Client) start() {
	life, stop := context.WithCancel(context.Background())
	c.stop = stop
	for _, r := range c.relays {
		_ = c.pool.add(life, r)
	}
	go func() {
		c.pool.wait()
		close(c.done)
	}()
}

// Dial pairs with the signer a bunker:// URI names: it connects, sends
// connect with the URI's secret, and fetches the user pubkey. ctx bounds
// this setup only; the Client lives until Close.
func Dial(ctx context.Context, uri string, opts ClientOptions) (*Client, error) {
	u, err := ParseURI(uri)
	if err != nil {
		return nil, err
	}
	c, err := newClient(u.SignerPubKey, u.Relays, opts)
	if err != nil {
		return nil, err
	}
	c.start()
	if err := c.pool.waitAny(ctx); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("%w: %v", ErrNoRelay, err)
	}
	params := []string{u.SignerPubKey, u.Secret, opts.Perms}
	if opts.Metadata != nil {
		meta, err := json.Marshal(opts.Metadata)
		if err == nil {
			params = append(params, string(meta))
		}
	}
	for len(params) > 1 && params[len(params)-1] == "" {
		params = params[:len(params)-1]
	}
	res, err := c.Call(ctx, nip46.MethodConnect, params...)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if res != "ack" && (u.Secret == "" || res != u.Secret) {
		_ = c.Close()
		return nil, fmt.Errorf("bunker: unexpected connect result %q", res)
	}
	if err := c.fetchUserPub(ctx); err != nil {
		_ = c.Close()
		return nil, err
	}
	return c, nil
}

// Resume reconnects to a signer paired earlier, using the saved Session's
// client key; no connect or secret is sent.
func Resume(ctx context.Context, s Session, opts ClientOptions) (*Client, error) {
	signer, err := nip46.ParsePubKey(s.SignerPubKey)
	if err != nil {
		return nil, fmt.Errorf("bunker: invalid session signer: %w", err)
	}
	opts.ClientKey = s.ClientKey
	c, err := newClient(signer, s.Relays, opts)
	if err != nil {
		return nil, err
	}
	c.start()
	if err := c.pool.waitAny(ctx); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("%w: %v", ErrNoRelay, err)
	}
	if err := c.fetchUserPub(ctx); err != nil {
		_ = c.Close()
		return nil, err
	}
	if s.UserPubKey != "" && !strings.EqualFold(s.UserPubKey, c.userPub) {
		_ = c.Close()
		return nil, fmt.Errorf("bunker: signer now signs as %s, session says %s", c.userPub, s.UserPubKey)
	}
	return c, nil
}

func (c *Client) fetchUserPub(ctx context.Context) error {
	res, err := c.Call(ctx, nip46.MethodGetPublicKey)
	if err != nil {
		return err
	}
	pub, err := nip46.ParsePubKey(res)
	if err != nil {
		return fmt.Errorf("bunker: signer sent an invalid pubkey: %w", err)
	}
	c.mu.Lock()
	c.userPub = pub
	c.mu.Unlock()
	return nil
}

// Pairing waits for a signer to answer a nostrconnect:// URI.
type Pairing struct {
	c   *Client
	uri string
}

// NewPairing starts listening on relays and returns the nostrconnect://
// URI to show the user. Call Wait for the signer, or Close to give up.
func NewPairing(relays []string, opts ClientOptions) (*Pairing, error) {
	c, err := newClient("", relays, opts)
	if err != nil {
		return nil, err
	}
	if c.pairSecret, err = NewSecret(); err != nil {
		return nil, err
	}
	c.paired = make(chan struct{})

	q := url.Values{}
	for _, r := range c.relays {
		q.Add("relay", r)
	}
	q.Set("secret", c.pairSecret)
	if opts.Perms != "" {
		q.Set("perms", opts.Perms)
	}
	if m := opts.Metadata; m != nil {
		if m.Name != "" {
			q.Set("name", m.Name)
		}
		if m.Url != "" {
			q.Set("url", m.Url)
		}
		if m.Image != "" {
			q.Set("image", m.Image)
		}
	}
	uri := (&url.URL{Scheme: "nostrconnect", Host: c.clientPub, RawQuery: q.Encode()}).String()
	c.start()
	return &Pairing{c: c, uri: uri}, nil
}

// URI is the nostrconnect:// string to show.
func (p *Pairing) URI() string { return p.uri }

// Wait blocks until a signer answers the URI, then returns the Client.
// On error the pairing is closed.
func (p *Pairing) Wait(ctx context.Context) (*Client, error) {
	select {
	case <-p.c.paired:
	case <-ctx.Done():
		_ = p.c.Close()
		return nil, ctx.Err()
	case <-p.c.done:
		return nil, ErrClosed
	}
	if err := p.c.fetchUserPub(ctx); err != nil {
		_ = p.c.Close()
		return nil, err
	}
	return p.c, nil
}

// Close stops waiting.
func (p *Pairing) Close() error { return p.c.Close() }

// onEvent routes one response to its waiting call.
func (c *Client) onEvent(_ *relayclient.Connection, ev *nip01.Event) {
	if err := ev.Verify(); err != nil {
		return
	}
	scheme := nip46.TaggedEncryption(ev)
	resp, err := nip46.ParseResponseEventAs(ev, c.clientPriv, scheme)
	if err != nil {
		if resp, err = nip46.ParseResponseEventAs(ev, c.clientPriv, nip46.OtherEncryption(scheme)); err != nil {
			return
		}
	}

	c.mu.Lock()
	if c.signerPub == "" {
		// Awaiting a nostrconnect:// answer: the signer echoes our secret.
		if c.pairSecret != "" && subtle.ConstantTimeCompare([]byte(resp.Result), []byte(c.pairSecret)) == 1 {
			c.signerPub = strings.ToLower(ev.PubKey)
			close(c.paired)
		}
		c.mu.Unlock()
		return
	}
	if !strings.EqualFold(ev.PubKey, c.signerPub) {
		c.mu.Unlock()
		return
	}
	ch := c.pending[resp.RequestID]
	c.mu.Unlock()

	if resp.Result == "auth_url" && resp.Error != "" {
		if c.opts.OnAuthURL != nil {
			c.opts.OnAuthURL(resp.Error)
		}
		return
	}
	if ch != nil {
		select {
		case ch <- resp:
		default:
		}
	}
}

// Call sends one request and waits for its response. An error response
// comes back as a *nip46.Error.
func (c *Client) Call(ctx context.Context, method string, params ...string) (string, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return "", ErrClosed
	}
	signer := c.signerPub
	c.mu.Unlock()
	if signer == "" {
		return "", errors.New("bunker: not paired yet")
	}

	ev, id, err := nip46.NewRequestEvent(c.clientPriv, signer, method, params, c.opts.Encryption)
	if err != nil {
		return "", err
	}
	if err := ev.Sign(c.clientPriv); err != nil {
		return "", err
	}
	ch := make(chan *nip46.ResponseEvent, 1)
	c.mu.Lock()
	c.pending[id] = ch
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()

	if c.pool.broadcast(ev) == 0 {
		if err := c.pool.waitAny(ctx); err != nil {
			return "", fmt.Errorf("%w: %v", ErrNoRelay, err)
		}
		if c.pool.broadcast(ev) == 0 {
			return "", ErrNoRelay
		}
	}

	select {
	case resp := <-ch:
		if resp.Error != "" {
			return "", nip46.ParseError(resp.Error)
		}
		return resp.Result, nil
	case <-ctx.Done():
		return "", ctx.Err()
	case <-c.done:
		return "", ErrClosed
	}
}

// PubKey is the user pubkey the signer signs as.
func (c *Client) PubKey() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.userPub
}

// SignerPubKey is the pubkey the signer talks on.
func (c *Client) SignerPubKey() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.signerPub
}

// Session is what Resume needs to reconnect later.
func (c *Client) Session() Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	return Session{SignerPubKey: c.signerPub, UserPubKey: c.userPub, Relays: append([]string(nil), c.relays...), ClientKey: c.clientPriv}
}

// RelayStatuses reports each relay's connection state.
func (c *Client) RelayStatuses() []RelayStatus { return c.pool.statuses() }

// Ping checks the signer answers.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.Call(ctx, nip46.MethodPing)
	return err
}

// Logout ends the session on the signer's side.
func (c *Client) Logout(ctx context.Context) error {
	_, err := c.Call(ctx, nip46.MethodLogout)
	return err
}

// Sign signs ev in place. The signed event is verified and must match
// what was sent.
func (c *Client) Sign(ctx context.Context, ev *nip01.Event) error {
	draft := *ev
	draft.ID, draft.Sig = "", ""
	draft.PubKey = c.PubKey()
	if draft.Tags == nil {
		draft.Tags = [][]string{}
	}
	evJSON, err := json.Marshal(&draft)
	if err != nil {
		return err
	}
	result, err := c.Call(ctx, nip46.MethodSignEvent, string(evJSON))
	if err != nil {
		return err
	}
	var signed nip01.Event
	if err := json.Unmarshal([]byte(result), &signed); err != nil {
		return fmt.Errorf("bunker: malformed signed event: %w", err)
	}
	if err := signed.Verify(); err != nil {
		return fmt.Errorf("bunker: signer returned an invalid event: %w", err)
	}
	if signed.Kind != draft.Kind || signed.Content != draft.Content || signed.CreatedAt != draft.CreatedAt ||
		!reflect.DeepEqual(signed.Tags, draft.Tags) || !strings.EqualFold(signed.PubKey, draft.PubKey) {
		return errors.New("bunker: signer returned a different event than requested")
	}
	*ev = signed
	return nil
}

// Encrypt asks the signer to encrypt plaintext to peerPubKey.
func (c *Client) Encrypt(ctx context.Context, scheme, peerPubKey, plaintext string) (string, error) {
	method, err := nip46.MethodFor(scheme, true)
	if err != nil {
		return "", err
	}
	return c.Call(ctx, method, peerPubKey, plaintext)
}

// Decrypt asks the signer to decrypt ciphertext from peerPubKey.
func (c *Client) Decrypt(ctx context.Context, scheme, peerPubKey, ciphertext string) (string, error) {
	method, err := nip46.MethodFor(scheme, false)
	if err != nil {
		return "", err
	}
	return c.Call(ctx, method, peerPubKey, ciphertext)
}

// Close disconnects. Pending calls fail with ErrClosed.
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	if c.stop != nil {
		c.stop()
		<-c.done
	}
	return nil
}
