package nip86

import (
	"context"
	"fmt"
	"sort"
)

// Method implements one NIP-86 method. caller is the pubkey that authenticated,
// so a method can scope what it does to who asked.
type Method func(ctx context.Context, caller string, req Request) (any, error)

// Router dispatches a Request to a registered Method.
//
// Visible, when set, decides which methods a given caller may see and use. The
// spec allows supportedmethods to be customised per authenticated user, and a
// method hidden from a caller is also refused to that caller -- otherwise the
// list would be advisory and the hiding cosmetic.
type Router struct {
	methods map[string]Method
	Visible func(caller, method string) bool
}

// NewRouter returns a Router that answers supportedmethods for itself. Register
// your own supportedmethods to override it.
func NewRouter() *Router {
	r := &Router{methods: make(map[string]Method)}
	r.Handle(MethodSupportedMethods, func(_ context.Context, caller string, _ Request) (any, error) {
		return r.MethodsFor(caller), nil
	})
	return r
}

// Handle registers m under name, replacing any previous registration.
func (r *Router) Handle(name string, m Method) {
	r.methods[name] = m
}

// MethodsFor lists the methods caller may use, sorted so the answer is stable.
func (r *Router) MethodsFor(caller string) []string {
	names := make([]string, 0, len(r.methods))
	for name := range r.methods {
		if r.Visible != nil && !r.Visible(caller, name) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Dispatch runs req as caller and returns the response to serialize. A method's
// error becomes the response's error field: per the spec that is still an HTTP
// 200, since only authentication failures are status codes.
func (r *Router) Dispatch(ctx context.Context, caller string, req Request) Response {
	m, ok := r.methods[req.Method]
	if !ok || (r.Visible != nil && !r.Visible(caller, req.Method)) {
		// A method the caller may not use is reported as unknown rather than
		// forbidden, so the endpoint does not confirm what it can do for
		// someone else.
		return Response{Error: fmt.Errorf("%w: %s", ErrUnknownMethod, req.Method).Error()}
	}

	result, err := m(ctx, caller, req)
	if err != nil {
		return Response{Error: err.Error()}
	}
	return Response{Result: result}
}
