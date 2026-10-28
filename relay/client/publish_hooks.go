package client

import (
	"context"

	"github.com/ohstr/nmilat/nip01"
)

type publishFilterKey struct{}
type afterPublishKey struct{}

// WithPublishFilter is a test hook: keep is asked before a request event is
// sent, and one it refuses is dropped as if lost on the way. It applies to
// NWCClient calls made with the returned context; nipcash/client's private
// transport reads the same hook.
func WithPublishFilter(ctx context.Context, keep func(*nip01.Event) bool) context.Context {
	return context.WithValue(ctx, publishFilterKey{}, keep)
}

// WithAfterPublish is a test hook: f runs right after a request event was sent.
func WithAfterPublish(ctx context.Context, f func()) context.Context {
	return context.WithValue(ctx, afterPublishKey{}, f)
}

// PublishFilterFrom is the hook WithPublishFilter set on ctx, nil when none.
func PublishFilterFrom(ctx context.Context) func(*nip01.Event) bool {
	f, _ := ctx.Value(publishFilterKey{}).(func(*nip01.Event) bool)
	return f
}

// AfterPublishFrom is the hook WithAfterPublish set on ctx, nil when none.
func AfterPublishFrom(ctx context.Context) func() {
	f, _ := ctx.Value(afterPublishKey{}).(func())
	return f
}
