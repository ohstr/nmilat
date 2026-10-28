package client

import (
	"errors"
	"fmt"
	"testing"

	"github.com/ohstr/nmilat/nipcash/transport"
)

func TestErrHubUnusableIsTheTransportError(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", transport.ErrHubUnusable)
	if !errors.Is(err, ErrHubUnusable) {
		t.Fatal("client.ErrHubUnusable does not match transport.ErrHubUnusable")
	}
}
