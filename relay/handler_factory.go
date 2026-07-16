package relay

import (
	"sync"
)

var (
	_handlers     []RequestHandler
	_handlersOnce sync.Once
)

// getRequestHandlers returns the shared chain of handlers.
// Since our handlers (NIP50, Cache, Standard) are currently state-less,
// we can reuse the same instances to avoid allocation on every request.
func getRequestHandlers() []RequestHandler {
	_handlersOnce.Do(func() {
		_handlers = []RequestHandler{
			&NIP50Handler{},
			&CacheHandler{},
			&MembershipRequestHandler{},
			&StandardRequestHandler{},
		}
	})
	return _handlers
}
