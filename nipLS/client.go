package nipLS

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip46"
)

// ErrConnClosed means the signer hung up without answering.
var ErrConnClosed = errors.New("nipLS: signer closed the connection")

// Client talks to a signer over its unix socket. It is safe for
// concurrent use; calls are serialized on the one connection. After a
// transport error (including a cancelled ctx mid-call) the connection is
// out of step with the server, so every later call returns that error:
// Dial again.
type Client struct {
	mu     sync.Mutex
	conn   net.Conn
	sc     *bufio.Scanner
	seq    int
	pub    string
	broken error
}

// Dial connects to uri (bunker+unix://, unix:// or an absolute path) and
// fetches the signer's pubkey.
func Dial(ctx context.Context, uri string) (*Client, error) {
	path, err := ParseURI(uri)
	if err != nil {
		return nil, err
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	c, err := NewClient(ctx, conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return c, nil
}

// NewClient wraps an open connection to a signer and fetches its pubkey.
// The Client owns conn from here on.
func NewClient(ctx context.Context, conn net.Conn) (*Client, error) {
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 64*1024), MaxMessageSize)
	c := &Client{conn: conn, sc: sc}
	pub, err := c.Call(ctx, nip46.MethodGetPublicKey)
	if err != nil {
		return nil, err
	}
	if c.pub, err = ParsePubKey(pub); err != nil {
		return nil, fmt.Errorf("nipLS: signer sent an invalid pubkey: %w", err)
	}
	return c, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// PubKey is the signer's pubkey, lowercase hex, fetched when connecting.
func (c *Client) PubKey() string { return c.pub }

// Call sends one request and waits for its response. An error response
// comes back as an *Error.
func (c *Client) Call(ctx context.Context, method string, params ...string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.broken != nil {
		return "", c.broken
	}
	result, err := c.call(ctx, method, params)
	var e *Error
	if err != nil && !errors.As(err, &e) {
		// The conn deadline can fire a hair before ctx reports it.
		var ne net.Error
		if ctx.Err() != nil {
			err = ctx.Err()
		} else if dl, ok := ctx.Deadline(); ok && !time.Now().Before(dl) && errors.As(err, &ne) && ne.Timeout() {
			err = context.DeadlineExceeded
		}
		c.broken = err
	}
	return result, err
}

func (c *Client) call(ctx context.Context, method string, params []string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = c.conn.SetDeadline(dl)
	} else {
		_ = c.conn.SetDeadline(time.Time{})
	}
	stop := context.AfterFunc(ctx, func() { _ = c.conn.SetDeadline(time.Unix(1, 0)) })
	defer stop()

	c.seq++
	id := strconv.Itoa(c.seq)
	if params == nil {
		params = []string{}
	}
	line, err := json.Marshal(nip46.Request{RequestID: id, Method: method, Params: params})
	if err != nil {
		return "", err
	}
	if _, err := c.conn.Write(append(line, '\n')); err != nil {
		return "", err
	}
	if !c.sc.Scan() {
		if err := c.sc.Err(); err != nil {
			return "", err
		}
		return "", ErrConnClosed
	}
	var resp nip46.Response
	if err := json.Unmarshal(c.sc.Bytes(), &resp); err != nil {
		return "", fmt.Errorf("nipLS: malformed signer response: %w", err)
	}
	if resp.RequestID != id {
		return "", fmt.Errorf("nipLS: signer answered request %q, want %q", resp.RequestID, id)
	}
	if resp.Error != "" {
		return "", parseWireError(resp.Error)
	}
	return resp.Result, nil
}

// Ping checks the signer answers.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.Call(ctx, nip46.MethodPing)
	return err
}

// Sign signs ev in place.
func (c *Client) Sign(ctx context.Context, ev *nip01.Event) error {
	return c.SignWithAttestations(ctx, ev, nil)
}

// SignWithAttestations signs ev in place, passing attestations as
// sign_event's params[1] for a policy that requires them. The signed event
// is verified and must match what was sent.
func (c *Client) SignWithAttestations(ctx context.Context, ev *nip01.Event, attestations []*nip01.Event) error {
	draft := *ev
	draft.ID, draft.Sig = "", ""
	if draft.Tags == nil {
		draft.Tags = [][]string{}
	}
	evJSON, err := json.Marshal(&draft)
	if err != nil {
		return err
	}
	params := []string{string(evJSON)}
	if len(attestations) > 0 {
		attJSON, err := json.Marshal(attestations)
		if err != nil {
			return err
		}
		params = append(params, string(attJSON))
	}
	result, err := c.Call(ctx, nip46.MethodSignEvent, params...)
	if err != nil {
		return err
	}
	var signed nip01.Event
	if err := json.Unmarshal([]byte(result), &signed); err != nil {
		return fmt.Errorf("nipLS: malformed signed event: %w", err)
	}
	if err := signed.Verify(); err != nil {
		return fmt.Errorf("nipLS: signer returned an invalid event: %w", err)
	}
	if signed.Kind != draft.Kind || signed.Content != draft.Content || signed.CreatedAt != draft.CreatedAt ||
		!reflect.DeepEqual(signed.Tags, draft.Tags) || !strings.EqualFold(signed.PubKey, c.pub) {
		return errors.New("nipLS: signer returned a different event than requested")
	}
	*ev = signed
	return nil
}

// Encrypt asks the signer to encrypt plaintext to peerPubKey. scheme is
// nip46.EncryptionNIP04 or nip46.EncryptionNIP44V2.
func (c *Client) Encrypt(ctx context.Context, scheme, peerPubKey, plaintext string) (string, error) {
	method, err := cryptoMethod(scheme, true)
	if err != nil {
		return "", err
	}
	return c.Call(ctx, method, peerPubKey, plaintext)
}

// Decrypt asks the signer to decrypt ciphertext from peerPubKey.
func (c *Client) Decrypt(ctx context.Context, scheme, peerPubKey, ciphertext string) (string, error) {
	method, err := cryptoMethod(scheme, false)
	if err != nil {
		return "", err
	}
	return c.Call(ctx, method, peerPubKey, ciphertext)
}

func cryptoMethod(scheme string, encrypt bool) (string, error) {
	switch {
	case scheme == nip46.EncryptionNIP04 && encrypt:
		return nip46.MethodNIP04Encrypt, nil
	case scheme == nip46.EncryptionNIP04:
		return nip46.MethodNIP04Decrypt, nil
	case scheme == nip46.EncryptionNIP44V2 && encrypt:
		return nip46.MethodNIP44Encrypt, nil
	case scheme == nip46.EncryptionNIP44V2:
		return nip46.MethodNIP44Decrypt, nil
	}
	return "", fmt.Errorf("%w: %q", nip46.ErrUnsupportedEncryption, scheme)
}
