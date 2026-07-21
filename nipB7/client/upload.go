package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ohstr/nmilat/nip01"
	"github.com/ohstr/nmilat/nipB7"
)

// UploadRequest describes a blob to send to PUT /upload or PUT /media.
type UploadRequest struct {
	Body        io.Reader
	Size        int64 // sets Content-Length when > 0; otherwise the transport chooses (typically chunked)
	ContentType string
	Auth        *nip01.Event // signed kind:24242 token; required by most servers for upload/media
}

func (c *Client) putBlob(ctx context.Context, path, server string, req UploadRequest) (*nipB7.BlobDescriptor, error) {
	u, err := joinPath(server, path)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, u, req.Body)
	if err != nil {
		return nil, err
	}
	if req.Size > 0 {
		httpReq.ContentLength = req.Size
	}
	if req.ContentType != "" {
		httpReq.Header.Set("Content-Type", req.ContentType)
	}
	if err := setAuthHeader(httpReq, req.Auth); err != nil {
		return nil, err
	}

	resp, err := c.httpClient().Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, newResponseError(server, resp)
	}

	var descriptor nipB7.BlobDescriptor
	if err := json.NewDecoder(resp.Body).Decode(&descriptor); err != nil {
		return nil, fmt.Errorf("nipB7/client: decoding blob descriptor: %w", err)
	}
	if err := descriptor.Validate(); err != nil {
		return nil, fmt.Errorf("nipB7/client: server returned invalid blob descriptor: %w", err)
	}
	return &descriptor, nil
}

// Upload sends a blob to PUT /upload (BUD-02), streaming req.Body rather
// than buffering it, and returns the server's Blob Descriptor.
func (c *Client) Upload(ctx context.Context, server string, req UploadRequest) (*nipB7.BlobDescriptor, error) {
	return c.putBlob(ctx, "/upload", server, req)
}

// Media sends a blob to PUT /media (BUD-05) for server-side optimization,
// returning the optimized blob's Descriptor.
func (c *Client) Media(ctx context.Context, server string, req UploadRequest) (*nipB7.BlobDescriptor, error) {
	return c.putBlob(ctx, "/media", server, req)
}

func (c *Client) headPreflight(ctx context.Context, path, server string, req nipB7.UploadRequirements, auth *nip01.Event) error {
	u, err := joinPath(server, path)
	if err != nil {
		return err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return err
	}
	req.SetHeaders(httpReq.Header)
	if err := setAuthHeader(httpReq, auth); err != nil {
		return err
	}

	resp, err := c.httpClient().Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return newResponseError(server, resp)
	}
	return nil
}

// HeadUpload performs the BUD-06 pre-flight check (HEAD /upload) so a
// client can learn whether a PUT /upload would be accepted — e.g. a 402
// PaymentRequiredError, or a 413/415 policy rejection — before sending the
// blob itself.
func (c *Client) HeadUpload(ctx context.Context, server string, req nipB7.UploadRequirements, auth *nip01.Event) error {
	return c.headPreflight(ctx, "/upload", server, req, auth)
}

// HeadMedia performs BUD-05's HEAD /media pre-flight check, the /media
// analogue of HeadUpload.
func (c *Client) HeadMedia(ctx context.Context, server string, req nipB7.UploadRequirements, auth *nip01.Event) error {
	return c.headPreflight(ctx, "/media", server, req, auth)
}
