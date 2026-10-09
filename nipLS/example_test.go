package nipLS_test

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipLS"
)

// Sign through a signer running in another process.
func ExampleDial() {
	ctx := context.Background()
	c, err := nipLS.Dial(ctx, "bunker+unix:///run/signer/agent.sock")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	ev := &nip01.Event{Kind: 1, Content: "hello", Tags: [][]string{}}
	switch err := c.Sign(ctx, ev); {
	case errors.Is(err, nipLS.ErrDenied):
		log.Printf("policy refused: %v", err)
	case err != nil:
		log.Fatal(err)
	}
}

// Run a signer that holds the key and signs only kind 1 notes.
func ExampleServer() {
	key, err := nipLS.NewLocalKey("nsec1...")
	if err != nil {
		log.Fatal(err)
	}
	srv, err := nipLS.NewServer(nipLS.ServerConfig{
		Key: key,
		Policy: nipLS.PolicyFunc(func(_ context.Context, r *nipLS.Request) error {
			if r.Event != nil && r.Event.Kind == 1 {
				return nil
			}
			return nipLS.Deny("only kind 1 notes")
		}),
		OnDecision: func(d nipLS.Decision) {
			log.Printf("%s allowed=%v err=%v", d.Request.Method, d.Allowed(), d.Err)
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := srv.ListenAndServe(ctx, "/run/signer/agent.sock", nipLS.ListenOptions{Mode: 0o660}); err != nil {
		log.Fatal(err)
	}
}

// Code that signs can take a nipLS.Signer and not care where the key is.
func ExampleSigner() {
	publish := func(ctx context.Context, s nipLS.Signer, content string) error {
		ev := &nip01.Event{Kind: 1, Content: content, Tags: [][]string{}}
		return s.Sign(ctx, ev)
	}
	var s nipLS.Signer
	var err error
	if uri := os.Getenv("SIGNER"); nipLS.IsURI(uri) {
		s, err = nipLS.Dial(context.Background(), uri) // key in a sidecar
	} else {
		s, err = nipLS.NewLocalKey(os.Getenv("NSEC")) // key in this process
	}
	if err != nil {
		log.Fatal(err)
	}
	_ = publish(context.Background(), s, "hi")
}
