package client

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	"github.com/ohstr/nmilat/nip01"
)

// Report submits a signed BUD-09 blob-report event to server's PUT /report
// endpoint. The report is self-authenticating via its own Nostr signature,
// so unlike other write operations here it carries no separate BUD-11
// Authorization header.
func (c *Client) Report(ctx context.Context, server string, report *nip01.Event) error {
	u, err := joinPath(server, "/report")
	if err != nil {
		return err
	}

	payload, err := json.Marshal(report)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= 400 {
		return newResponseError(server, resp)
	}
	return nil
}
