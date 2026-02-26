package internal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"
)

const coordPrefix = "http://coord"

type CoordinatorClient struct {
	client *http.Client
}

func NewCoordinatorClient(socketPath string) *CoordinatorClient {
	return &CoordinatorClient{
		client: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					return (&net.Dialer{Timeout: 200 * time.Millisecond}).DialContext(ctx, "unix", socketPath)
				},
			},
		},
	}
}

// Register registers a public key with the coordinator.
func (c *CoordinatorClient) Register(ctx context.Context, pubKey ed25519.PublicKey) error {
	req := RegisterRequest{Ed25519PubKey: pubKey}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal register request: %w", err)
	}

	hReq, err := http.NewRequestWithContext(ctx, http.MethodPost, coordPrefix+"/register", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	hReq.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(hReq)
	if err != nil {
		return fmt.Errorf("post register: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("register: unexpected status %d", resp.StatusCode)
	}

	return nil
}

// Start requests that the coordinator starts the chain.
func (c *CoordinatorClient) Start(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, coordPrefix+"/start", nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("post start: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("start: unexpected status %d", resp.StatusCode)
	}

	return nil
}

func (c *CoordinatorClient) AwaitGenesis(ctx context.Context) (Genesis, error) {
	var g Genesis
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, coordPrefix+"/genesis", nil)
	if err != nil {
		return g, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return g, fmt.Errorf("executing genesis request: %w", err)
	}
	defer resp.Body.Close()

	if err := json.NewDecoder(resp.Body).Decode(&g); err != nil {
		return g, fmt.Errorf("decoding genesis: %w", err)
	}

	return g, nil
}
