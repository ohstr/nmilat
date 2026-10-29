package nipLS

// NIP-LS §Security Considerations: a policy's check and spend is atomic with
// the operation; §Wire format: responses are matched by id.

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip46"
)

// A policy that spends a one-time approval with a gap between check and spend
// still lets only one of two concurrent requests through.
func TestOneTimeApprovalSpentOnce(t *testing.T) {
	var used atomic.Bool
	policy := PolicyFunc(func(_ context.Context, r *Request) error {
		if len(r.Attestations) != 1 {
			return Deny("needs an approval")
		}
		if used.Load() {
			return Deny("approval already spent")
		}
		time.Sleep(20 * time.Millisecond)
		used.Store(true)
		return nil
	})
	h := start(t, ServerConfig{Policy: policy})
	approval := &nip01.Event{Kind: 1, Content: "approve", CreatedAt: 1}
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		c := dial(t, h)
		wg.Add(1)
		go func() {
			defer wg.Done()
			ev := &nip01.Event{Kind: 1, Content: "spend", CreatedAt: 1}
			if err := c.SignWithAttestations(context.Background(), ev, []*nip01.Event{approval}); err == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d requests signed with one approval", ok.Load())
	}
}

// A response carrying another request's id is refused and the connection is not reused.
func TestClientMatchesResponseID(t *testing.T) {
	a, b := net.Pipe()
	defer func() { _ = a.Close() }()
	go func() {
		dec := json.NewDecoder(b)
		for {
			var req nip46.Request
			if dec.Decode(&req) != nil {
				return
			}
			id := req.RequestID
			result := "pong"
			if req.Method == nip46.MethodGetPublicKey {
				result = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
			} else {
				id = "999"
			}
			line, _ := json.Marshal(nip46.Response{RequestID: id, Result: result})
			_, _ = b.Write(append(line, '\n'))
		}
	}()
	c, err := NewClient(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Ping(context.Background()); err == nil {
		t.Fatal("a response with another id was accepted")
	}
	if err := c.Ping(context.Background()); err == nil || errors.Is(err, ErrDenied) {
		t.Fatalf("connection reused after an out-of-step response: %v", err)
	}
}

// quotaPolicy allows limit requests of method, with a gap between check and
// spend that a racing request would slip through without the server's lock.
func quotaPolicy(method string, limit int32) Policy {
	var used atomic.Int32
	return PolicyFunc(func(_ context.Context, r *Request) error {
		if r.Method != method {
			return nil
		}
		if used.Load() >= limit {
			return Deny("quota spent")
		}
		time.Sleep(20 * time.Millisecond)
		used.Add(1)
		return nil
	})
}

// concurrently runs n calls at once, each on its own connection, and counts
// those that succeed.
func concurrently(t *testing.T, h *harness, n int, call func(*Client) error) int32 {
	t.Helper()
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		c := dial(t, h)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if call(c) == nil {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	return ok.Load()
}

// An encrypt or decrypt quota is spent once per request, also under
// concurrent requests; a quota that covers them all lets them all through.
func TestCryptoQuotaSpentOnce(t *testing.T) {
	ctx := context.Background()
	peer := mustPeer(t)
	encrypt := func(c *Client) error {
		_, err := c.Encrypt(ctx, nip46.EncryptionNIP44V2, peer.PubKey(), "x")
		return err
	}
	if got := concurrently(t, start(t, ServerConfig{Policy: quotaPolicy(nip46.MethodNIP44Encrypt, 1)}), 2, encrypt); got != 1 {
		t.Fatalf("encrypts allowed with a quota of 1: %d", got)
	}
	if got := concurrently(t, start(t, ServerConfig{Policy: quotaPolicy(nip46.MethodNIP44Encrypt, 3)}), 3, encrypt); got != 3 {
		t.Fatalf("encrypts allowed with a quota of 3: %d", got)
	}
	h := start(t, ServerConfig{Policy: quotaPolicy(nip46.MethodNIP44Decrypt, 1)})
	payload, err := peer.Encrypt(ctx, nip46.EncryptionNIP44V2, dial(t, h).PubKey(), "y")
	if err != nil {
		t.Fatal(err)
	}
	decrypt := func(c *Client) error {
		_, err := c.Decrypt(ctx, nip46.EncryptionNIP44V2, peer.PubKey(), payload)
		return err
	}
	if got := concurrently(t, h, 2, decrypt); got != 1 {
		t.Fatalf("decrypts allowed with a quota of 1: %d", got)
	}
}
