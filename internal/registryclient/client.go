package registryclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// Client fetches attestation definitions from a fikua-lab-attestation-registry
// instance's JSON API.
type Client struct {
	baseURL string
	http    *http.Client
}

// New builds a Client against the registry at baseURL (e.g.
// "https://attestation-registry.fikua.com").
func New(baseURL string) *Client {
	return &Client{baseURL: baseURL, http: &http.Client{}}
}

// ListSchemes fetches every registered attestation definition.
func (c *Client) ListSchemes(ctx context.Context) ([]Definition, error) {
	var defs []Definition
	if err := c.get(ctx, "/api/v1/schemes", &defs); err != nil {
		return nil, err
	}
	return defs, nil
}

// GetScheme fetches one attestation definition by scheme id.
func (c *Client) GetScheme(ctx context.Context, id string) (*Definition, error) {
	var def Definition
	if err := c.get(ctx, "/api/v1/schemes/"+url.PathEscape(id), &def); err != nil {
		return nil, err
	}
	return &def, nil
}

func (c *Client) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("registryclient: GET %s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("registryclient: GET %s: unexpected status %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("registryclient: GET %s: decoding response: %w", path, err)
	}
	return nil
}
