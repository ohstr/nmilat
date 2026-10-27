package client

import "github.com/ohstr/nmilat/nipcash/transport"

// ErrHubUnusable is a Hub the client sends no call carrying a request_id to:
// its announcement carries no max_request_age of at least 60 seconds, or its
// newest announcement was rejected. It is transport.ErrHubUnusable, so
// errors.Is matches either.
var ErrHubUnusable = transport.ErrHubUnusable
