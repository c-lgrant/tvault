package api

import (
	"encoding/json"
	"net/url"
)

// Principal identifies who a key (or session) authenticates as.
type Principal struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name"`
}

// WhoamiResult is GET /api/agents/whoami, answered for every principal type.
type WhoamiResult struct {
	Principal Principal `json:"principal"`
	UserID    string    `json:"userId"`
	Kind      string    `json:"kind"`
	Scopes    []string  `json:"scopes"`
	ExpiresAt *string   `json:"expiresAt"`
}

// Whoami asks the server which principal the client's credentials resolve to.
func (c *Client) Whoami() (*WhoamiResult, error) {
	body, err := c.doRequest("GET", "/api/agents/whoami", nil, nil)
	if err != nil {
		return nil, err
	}
	var res WhoamiResult
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// CreatedBy records which principal minted a key.
type CreatedBy struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Key is the list shape of a scoped key. The secret is never listed.
type Key struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Scopes     []string  `json:"scopes"`
	Status     string    `json:"status"`
	ExpiresAt  *string   `json:"expiresAt"`
	CreatedAt  string    `json:"createdAt"`
	LastUsedAt *string   `json:"lastUsedAt"`
	CreatedBy  CreatedBy `json:"createdBy"`
}

// KeyGrant is one service grant on a key. Source says how the grant came to
// exist (e.g. directly granted vs. inherited), as reported by the server.
type KeyGrant struct {
	ServiceName    string  `json:"serviceName"`
	RefreshPolicy  string  `json:"refreshPolicy"`
	Source         string  `json:"source"`
	GrantedAt      string  `json:"grantedAt"`
	GrantExpiresAt *string `json:"grantExpiresAt"`
}

// GrantKeyResult is the POST /api/keys/{id}/grants response.
type GrantKeyResult struct {
	Success        bool    `json:"success"`
	ServiceName    string  `json:"serviceName"`
	GrantExpiresAt *string `json:"grantExpiresAt"`
	RefreshPolicy  string  `json:"refreshPolicy"`
	Source         string  `json:"source"`
}

// KeyDetail is GET /api/keys/{id}: the list item plus its grants.
type KeyDetail struct {
	Key
	Grants []KeyGrant `json:"grants"`
}

// GetKey returns one key with its grants.
func (c *Client) GetKey(id string) (*KeyDetail, error) {
	body, err := c.doRequest("GET", "/api/keys/"+url.PathEscape(id), nil, nil)
	if err != nil {
		return nil, err
	}
	var res KeyDetail
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// GrantKey grants a service to a key. expiresInHours <= 0 omits the field
// (no grant expiry).
func (c *Client) GrantKey(id, service string, expiresInHours int) (*GrantKeyResult, error) {
	payload := map[string]any{"serviceName": service}
	if expiresInHours > 0 {
		payload["expiresInHours"] = expiresInHours
	}
	body, err := c.doRequest("POST", "/api/keys/"+url.PathEscape(id)+"/grants", payload, nil)
	if err != nil {
		return nil, err
	}
	var res GrantKeyResult
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// UngrantKey removes a service grant from a key.
func (c *Client) UngrantKey(id, service string) error {
	_, err := c.doRequest("DELETE", "/api/keys/"+url.PathEscape(id)+"/grants/"+url.PathEscape(service), nil, nil)
	return err
}

// CreateKeyResult carries the freshly minted key — shown to the user once.
type CreateKeyResult struct {
	ID        string   `json:"id"`
	Key       string   `json:"key"`
	Name      string   `json:"name"`
	Scopes    []string `json:"scopes"`
	ExpiresAt *string  `json:"expiresAt"`
	CreatedAt string   `json:"createdAt"`
}

// CreateKey mints a scoped key. expiresAt is an ISO8601 timestamp, or nil for
// a key that never expires (sent as JSON null).
func (c *Client) CreateKey(name string, scopes []string, expiresAt *string) (*CreateKeyResult, error) {
	payload := map[string]any{"name": name, "scopes": scopes, "expiresAt": expiresAt}
	body, err := c.doRequest("POST", "/api/keys", payload, nil)
	if err != nil {
		return nil, err
	}
	var res CreateKeyResult
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// ListKeys returns the account's scoped keys.
func (c *Client) ListKeys() ([]Key, error) {
	body, err := c.doRequest("GET", "/api/keys", nil, nil)
	if err != nil {
		return nil, err
	}
	var res struct {
		Keys []Key `json:"keys"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	return res.Keys, nil
}

// RotateKeyResult carries the replacement secret — shown once.
type RotateKeyResult struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

// RotateKey replaces a key's secret, invalidating the old one.
func (c *Client) RotateKey(id string) (*RotateKeyResult, error) {
	body, err := c.doRequest("POST", "/api/keys/"+url.PathEscape(id)+"/rotate", nil, nil)
	if err != nil {
		return nil, err
	}
	var res RotateKeyResult
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// RevokeKey permanently revokes a key.
func (c *Client) RevokeKey(id string) error {
	_, err := c.doRequest("DELETE", "/api/keys/"+url.PathEscape(id), nil, nil)
	return err
}

// RotateAgentKeyResult carries the agent's replacement key — shown once.
type RotateAgentKeyResult struct {
	ID     string `json:"id"`
	APIKey string `json:"apiKey"`
}

// RotateAgentKey replaces an agent's tvagent_* key.
func (c *Client) RotateAgentKey(id string) (*RotateAgentKeyResult, error) {
	body, err := c.doRequest("POST", "/api/agents/"+url.PathEscape(id)+"/rotate-key", nil, nil)
	if err != nil {
		return nil, err
	}
	var res RotateAgentKeyResult
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	return &res, nil
}
