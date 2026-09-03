package client

import (
	"context"
	"net/http"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipB7"
)

// Delete removes a blob from server (BUD-12's DELETE /<sha256>). auth is
// required by the spec ("Authorization is required and missing or invalid"
// otherwise returns 401) and, per BUD-11's note on delete tokens, should be
// scoped to exactly this hash.
func (c *Client) Delete(ctx context.Context, server, hash string, auth *nip01.Event) error {
	u, err := nipB7.BuildServerURL(server, hash, "")
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, u, nil)
	if err != nil {
		return err
	}
	if err := setAuthHeader(req, auth); err != nil {
		return err
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return newResponseError(server, resp)
	}
	return nil
}
