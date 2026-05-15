package api

import "encoding/json"

// WebhookBindResult is the backend's POST /api/vault/webhook-bind response.
type WebhookBindResult struct {
	Status              string   `json:"status"`
	VaultMode           string   `json:"vaultMode"`
	WebhookRegistered   bool     `json:"webhookRegistered"`
	WebhookCapabilities []string `json:"webhookCapabilities"`
}

// WebhookBind binds a deployed webhook to the user's vault. The CLI fetches
// code + webhookURL + hmacSecretHash from the webhook's /v1/register-url and
// passes them here; the backend completes the one-time-code exchange.
func (c *Client) WebhookBind(code, webhookURL, hmacSecretHash string) (*WebhookBindResult, error) {
	payload := map[string]string{
		"code":           code,
		"webhookUrl":     webhookURL,
		"hmacSecretHash": hmacSecretHash,
	}
	body, err := c.doRequest("POST", "/api/vault/webhook-bind", payload, nil)
	if err != nil {
		return nil, err
	}
	var res WebhookBindResult
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// WebhookInfo is the backend's stored webhook config (subset).
type WebhookInfo struct {
	URL              string `json:"url"`
	Status           string `json:"status"`
	LastHealthCheck  string `json:"lastHealthCheck"`
	LastHealthStatus string `json:"lastHealthStatus"`
}

// VaultWebhookStatus is the webhook-relevant subset of GET /api/vault/status.
type VaultWebhookStatus struct {
	VaultMode    string       `json:"vaultMode"`
	Webhook      *WebhookInfo `json:"webhook"`
	Capabilities []string     `json:"webhookCapabilities"`
}

// VaultWebhookInfo returns the backend's view of the bound webhook.
func (c *Client) VaultWebhookInfo() (*VaultWebhookStatus, error) {
	body, err := c.doRequest("GET", "/api/vault/status", nil, nil)
	if err != nil {
		return nil, err
	}
	var st VaultWebhookStatus
	if err := json.Unmarshal(body, &st); err != nil {
		return nil, err
	}
	return &st, nil
}
