package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Client uses a caller-owned HTTP client to communicate with the service.
type Client struct {
	HTTP      *http.Client
	BaseURL   string
	UserAgent string
}

func (c *Client) request(ctx context.Context, method, path string, query url.Values, body io.Reader) (*http.Request, error) {
	if c == nil || c.HTTP == nil {
		return nil, ErrNoClient
	}
	if ctx == nil {
		return nil, fmt.Errorf("request: %w", ErrTransport)
	}
	base := c.BaseURL
	if base == "" {
		base = "https://lotw.arrl.org"
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil {
		return nil, fmt.Errorf("request: %w", ErrTransport)
	}
	u.Path = strings.TrimRight(u.Path, "/") + path
	u.RawPath = ""
	u.RawQuery = query.Encode()
	u.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("request: %w", ErrTransport)
	}
	agent := c.UserAgent
	if agent == "" {
		agent = "go-gabbi"
	}
	req.Header.Set("User-Agent", agent)
	return req, nil
}

func (c *Client) do(req *http.Request, operation string) (*http.Response, error) {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, transportError(req.Context(), operation, err)
	}
	return resp, nil
}

func transportError(ctx context.Context, operation string, cause error) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%s: %w: %w", operation, ErrTransport, err)
	}
	if errors.Is(cause, context.Canceled) {
		return fmt.Errorf("%s: %w: %w", operation, ErrTransport, context.Canceled)
	}
	if errors.Is(cause, context.DeadlineExceeded) {
		return fmt.Errorf("%s: %w: %w", operation, ErrTransport, context.DeadlineExceeded)
	}
	return fmt.Errorf("%s: %w", operation, ErrTransport)
}
