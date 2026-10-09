package bunker_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip46"
	"github.com/ohstr/nmilat/nip46/bunker"
)

// Pair from a bunker:// URI and sign through the remote signer.
func ExampleDial() {
	ctx := context.Background()
	c, err := bunker.Dial(ctx, "bunker://<signer-pubkey>?relay=wss://relay.example&secret=...", bunker.ClientOptions{
		Perms:    "sign_event:1",
		Metadata: &nip46.Metadata{Name: "my app"},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	ev := &nip01.Event{Kind: 1, Content: "hello", Tags: [][]string{}}
	if err := c.Sign(ctx, ev); errors.Is(err, nip46.ErrDenied) {
		log.Printf("signer refused: %v", err)
	}
	saveSession(c.Session()) // Resume with it next time; no new secret needed
}

// Show a nostrconnect:// URI and wait for a signer to answer it.
func ExampleNewPairing() {
	p, err := bunker.NewPairing([]string{"wss://relay.example"}, bunker.ClientOptions{Metadata: &nip46.Metadata{Name: "my app"}})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("scan:", p.URI())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	c, err := p.Wait(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()
}

// Run a remote signer that signs only kind-1 notes for paired apps.
func ExampleServer() {
	key, err := nip46.NewLocalKey("nsec1...")
	if err != nil {
		log.Fatal(err)
	}
	paired := map[string]bool{}
	srv, err := bunker.NewServer(bunker.ServerConfig{
		Key:    key,
		Relays: []string{"wss://relay.example"},
		Policy: bunker.PolicyFunc(func(_ context.Context, c *bunker.Call) error {
			switch {
			case c.Method == nip46.MethodConnect: // presented a secret we armed
				paired[c.Client] = true
				return nil
			case !paired[c.Client]:
				return nip46.Deny("not paired")
			case c.Event != nil && c.Event.Kind != 1:
				return nip46.Deny("only kind 1 notes")
			}
			return nil
		}),
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	go func() { _ = srv.Run(ctx) }()

	uri, _ := srv.NewBunkerURI(5 * time.Minute)
	fmt.Println("paste into your app:", uri)
}

func saveSession(bunker.Session) {}
