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

// StoreTicket is the response shape of POST /api/vault/store-ticket. The
// ticket authorises the caller to push a token document directly to the
// user's webhook at <WebhookURL>/v1/store, bypassing Token Vault.
type StoreTicket struct {
	Ticket     string `json:"ticket"`
	WebhookURL string `json:"webhookUrl"`
	ExpiresIn  int    `json:"expiresIn"`
}

// VaultStoreTicket fetches a webhook-store ticket for the named service. Only
// valid for webhook-mode vaults; platform-mode users get a 400 from the API.
func (c *Client) VaultStoreTicket(serviceName string) (*StoreTicket, error) {
	body, err := c.doRequest("POST", "/api/vault/store-ticket",
		map[string]string{"serviceName": serviceName}, nil)
	if err != nil {
		return nil, err
	}
	var t StoreTicket
	if err := json.Unmarshal(body, &t); err != nil {
		return nil, err
	}
	return &t, nil
}
