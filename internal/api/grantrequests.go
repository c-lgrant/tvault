package api

import (
	"encoding/json"
	"net/url"

	"github.com/c-lgrant/tvault/internal/textsafe"
)

// GrantRequest is a key or agent's request for grants. The owner approves or
// denies it in the console; the request itself carries no authority.
type GrantRequest struct {
	RequestID      string           `json:"requestId"`
	Requester      Principal        `json:"requester"`
	Services       []string         `json:"services"`
	Reason         string           `json:"reason"`
	Status         string           `json:"status"` // pending | approved | denied | expired
	CreatedAt      string           `json:"createdAt"`
	ExpiresAt      string           `json:"expiresAt"`
	DecidedAt      *string          `json:"decidedAt"`
	Granted        []string         `json:"granted"`
	Skipped        []SkippedService `json:"skipped"`
	URL            string           `json:"url"`
	Uses           []string         `json:"uses,omitempty"`
	ExpiresInHours int              `json:"expiresInHours,omitempty"`
	// Change requests: Kind is "changes" and Results holds one entry per
	// action once the owner approved.
	Kind    string         `json:"kind,omitempty"`
	Results []ChangeResult `json:"results,omitempty"`
}

// ChangeResult is what happened to one action of an approved change request.
type ChangeResult struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Status       string `json:"status"` // done | skipped | failed
	Message      string `json:"message,omitempty"`
	AgentID      string `json:"agentId,omitempty"`
	KeyClaimedAt string `json:"keyClaimedAt,omitempty"`
}

// sanitize makes every server-provided string safe to print: control and
// escape characters come back quoted (textsafe), so a hostile or broken
// server can't repaint the terminal. A URL that is not plain http(s) is
// dropped, so the CLI never prints a javascript: or garbled link as "the
// approval link".
func (r *GrantRequest) sanitize() {
	r.RequestID = textsafe.Safe(r.RequestID)
	r.Status = textsafe.Safe(r.Status)
	r.CreatedAt = textsafe.Safe(r.CreatedAt)
	r.ExpiresAt = textsafe.Safe(r.ExpiresAt)
	r.Reason = textsafe.Safe(r.Reason)
	r.Requester.Name = textsafe.Safe(r.Requester.Name)
	safeAll(r.Services)
	safeAll(r.Granted)
	for i := range r.Skipped {
		r.Skipped[i].Service = textsafe.Safe(r.Skipped[i].Service)
		r.Skipped[i].Reason = textsafe.Safe(r.Skipped[i].Reason)
	}
	r.Kind = textsafe.Safe(r.Kind)
	for i := range r.Results {
		res := &r.Results[i]
		res.ID, res.Type, res.Status = textsafe.Safe(res.ID), textsafe.Safe(res.Type), textsafe.Safe(res.Status)
		res.Message, res.AgentID = textsafe.Safe(res.Message), textsafe.Safe(res.AgentID)
		res.KeyClaimedAt = textsafe.Safe(res.KeyClaimedAt)
	}
	if u, err := url.Parse(r.URL); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" ||
		textsafe.Safe(r.URL) != r.URL {
		r.URL = ""
	}
}

func safeAll(items []string) {
	for i := range items {
		items[i] = textsafe.Safe(items[i])
	}
}

// SkippedService is a requested service the approval did not grant, and why.
type SkippedService struct {
	Service string `json:"service"`
	Reason  string `json:"reason"`
}

// NewGrantRequest is the body of POST /api/grant-requests: either Services
// (grants for the caller) or Actions (a change request, sent as given).
type NewGrantRequest struct {
	Services       []string        `json:"services,omitempty"`
	Actions        json.RawMessage `json:"actions,omitempty"`
	Reason         string          `json:"reason"`
	Uses           []string        `json:"uses,omitempty"`
	ExpiresInHours int             `json:"expiresInHours,omitempty"`
}

// ClaimedKey is the key of an agent a change request created.
type ClaimedKey struct {
	AgentID string `json:"agentId"`
	APIKey  string `json:"apiKey"`
}

// ClaimAgentKey collects, once, the key of the agent that action actionID of
// the caller's approved change request created. The server issues a fresh key.
func (c *Client) ClaimAgentKey(requestID, actionID string) (*ClaimedKey, error) {
	path := "/api/grant-requests/" + url.PathEscape(requestID) + "/actions/" + url.PathEscape(actionID) + "/claim-key"
	body, err := c.doRequest("POST", path, nil, nil)
	if err != nil {
		return nil, err
	}
	var res ClaimedKey
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	res.AgentID = textsafe.Safe(res.AgentID)
	return &res, nil
}

// CreateGrantRequest asks the owner for grants for the calling key or agent.
// The result's URL is the console page where the owner decides.
func (c *Client) CreateGrantRequest(req NewGrantRequest) (*GrantRequest, error) {
	body, err := c.doRequest("POST", "/api/grant-requests", req, nil)
	if err != nil {
		return nil, err
	}
	var res GrantRequest
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	res.sanitize()
	return &res, nil
}

// GetGrantRequest reads one of the caller's own requests (another's is a 404).
func (c *Client) GetGrantRequest(id string) (*GrantRequest, error) {
	body, err := c.doRequest("GET", "/api/grant-requests/"+url.PathEscape(id), nil, nil)
	if err != nil {
		return nil, err
	}
	var res GrantRequest
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	res.sanitize()
	return &res, nil
}

// DropResult is POST /api/grants/drop: what was removed, and what was never held.
type DropResult struct {
	Dropped []string `json:"dropped"`
	NotHeld []string `json:"notHeld"`
}

// DropGrants removes grants the calling key or agent holds. No scope is
// needed: it only ever reduces the caller's own access.
func (c *Client) DropGrants(services []string) (*DropResult, error) {
	body, err := c.doRequest("POST", "/api/grants/drop", map[string][]string{"services": services}, nil)
	if err != nil {
		return nil, err
	}
	var res DropResult
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	safeAll(res.Dropped)
	safeAll(res.NotHeld)
	return &res, nil
}
