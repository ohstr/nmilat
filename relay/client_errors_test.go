package relay

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nip11"
	"github.com/ohstr/nmilat/wire"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A malformed authors value is the client's fault: CLOSED "invalid:", and
// nothing logged above debug.
func TestProcessRequest_BadAuthorIsInvalidNotLoggedAsError(t *testing.T) {
	for name, author := range map[string]string{"short": "abcd", "not hex": "zz"} {
		t.Run(name, func(t *testing.T) {
			var logs bytes.Buffer
			cfg := &SessionConfig{Logger: zerolog.New(&logs).Level(zerolog.InfoLevel)}
			sc := NewSessionContext(newStore(t), &ClientInfo{}, &nip11.Metadata{}, nil, nil, cfg)
			sess := &Session{SessionContext: sc}
			ctx := context.WithValue(context.Background(), sessionContextKey{}, sess)

			f := nip01.NewSubscriptionFilterGroup()
			f.Add(&nip01.SubscriptionFilter{Authors: []string{author}})
			go func() { _ = sess.ProcessPacket(ctx, &wire.RequestPacket{SubscriptionID: "s", Filters: f}) }()

			deadline := time.After(5 * time.Second)
			for {
				select {
				case p := <-sc.incoming:
					closed, ok := p.(*wire.ClosedSubscriptionResponse)
					if !ok {
						continue
					}
					assert.True(t, strings.HasPrefix(closed.Message, "invalid: "), closed.Message)
					assert.Empty(t, logs.String())
					return
				case <-deadline:
					t.Fatal("no CLOSED")
				}
			}
		})
	}
}

// Ordinary client behaviour ending a session is not a relay error.
func TestShouldLogError_ClientCausedSessionEnds(t *testing.T) {
	reset := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)}
	for name, err := range map[string]error{
		"read limit":       fmt.Errorf("unexpected error while processing payload: %w", websocket.ErrReadLimit),
		"connection reset": fmt.Errorf("unexpected error while processing payload: %w", reset),
	} {
		t.Run(name, func(t *testing.T) {
			require.False(t, shouldLogError(err))
		})
	}
	assert.True(t, shouldLogError(fmt.Errorf("store is broken")))
}
