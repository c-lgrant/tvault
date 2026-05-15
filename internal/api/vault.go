package api

import "encoding/json"

// VaultStatusResult is the subset of GET /api/vault/status the CLI uses.
// The backend response also carries storageBackend, encryptionMode, webhook
// details, etc.; we only surface lock state and mode.
type VaultStatusResult struct {
	IsLocked  bool   `json:"isLocked"`
	VaultMode string `json:"vaultMode"`
}

func (c *Client) VaultLock() error {
	_, err := c.doRequest("POST", "/api/vault/lock", nil, nil)
	return err
}

func (c *Client) VaultUnlock() error {
	_, err := c.doRequest("POST", "/api/vault/lock/clear", nil, nil)
	return err
}

func (c *Client) VaultStatus() (*VaultStatusResult, error) {
	body, err := c.doRequest("GET", "/api/vault/status", nil, nil)
	if err != nil {
		return nil, err
	}
	var st VaultStatusResult
	if err := json.Unmarshal(body, &st); err != nil {
		return nil, err
	}
	return &st, nil
}
