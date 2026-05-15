package api

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Agent is the list/show shape returned by the agents endpoints.
//
// NOTE: the backend keys the id field "id" (not "agentId" — the API docs are
// stale here; routes/agents.py returns "id"). On GET /api/agents/{id} the
// backend returns a "grants" array of grant objects (each with serviceName);
// the list endpoint returns "grantCount" instead. Grants here is populated
// from the single-agent GET via GetAgent.
type Agent struct {
	ID         string  `json:"id"`
	Name       string  `json:"name"`
	Status     string  `json:"status"` // "active" | "suspended"
	GrantCount int     `json:"grantCount,omitempty"`
	Grants     []Grant `json:"grants,omitempty"`
}

// Grant is one credential grant on an agent (subset of the backend grant doc).
type Grant struct {
	ServiceName    string `json:"serviceName"`
	RefreshPolicy  string `json:"refreshPolicy,omitempty"`
	GrantExpiresAt string `json:"grantExpiresAt,omitempty"`
}

// CreateAgentResult carries the freshly minted key — shown to the user once.
// The backend response keys the id field "id".
type CreateAgentResult struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	APIKey string `json:"apiKey"`
}

func (c *Client) ListAgents() ([]Agent, error) {
	body, err := c.doRequest("GET", "/api/agents", nil, nil)
	if err != nil {
		return nil, err
	}
	var agents []Agent
	if err := json.Unmarshal(body, &agents); err != nil {
		return nil, err
	}
	return agents, nil
}

func (c *Client) GetAgent(id string) (*Agent, error) {
	body, err := c.doRequest("GET", "/api/agents/"+id, nil, nil)
	if err != nil {
		return nil, err
	}
	var a Agent
	if err := json.Unmarshal(body, &a); err != nil {
		return nil, err
	}
	return &a, nil
}

// CreateAgent creates an agent. The backend's POST /api/agents body only
// accepts {name, description, mcpEnabled} — there is NO grants field, so
// grants cannot be set at creation time. Callers that want grants must follow
// up with AddGrants once the agent exists.
func (c *Client) CreateAgent(name string) (*CreateAgentResult, error) {
	payload := map[string]any{"name": name}
	body, err := c.doRequest("POST", "/api/agents", payload, nil)
	if err != nil {
		return nil, err
	}
	var res CreateAgentResult
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// DeleteAgents removes one (single endpoint) or many (bulk endpoint) agents.
// The bulk endpoint's BulkDeleteAgentsRequest pins the field name "agentIds".
func (c *Client) DeleteAgents(ids []string) error {
	if len(ids) == 1 {
		_, err := c.doRequest("DELETE", "/api/agents/"+ids[0], nil, nil)
		return err
	}
	_, err := c.doRequest("DELETE", "/api/agents/bulk",
		map[string][]string{"agentIds": ids}, nil)
	return err
}

// SetAgentStatus suspends ("suspended") or resumes ("active") an agent via
// PATCH /api/agents/{id} with a "status" field.
func (c *Client) SetAgentStatus(id, status string) error {
	_, err := c.doRequest("PATCH", "/api/agents/"+id,
		map[string]string{"status": status}, nil)
	return err
}

// ListGrants returns an agent's granted service names. The backend has no
// dedicated grants-list route; GET /api/agents/{id} embeds a "grants" array.
func (c *Client) ListGrants(agentID string) ([]string, error) {
	a, err := c.GetAgent(agentID)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(a.Grants))
	for _, g := range a.Grants {
		out = append(out, g.ServiceName)
	}
	return out, nil
}

// GrantResult records the per-service outcome of a multi-service grant or
// revoke operation. Because the backend has no bulk grant/revoke route, the
// CLI issues one HTTP call per service; this lets the caller report exactly
// which services succeeded, which failed, and which were skipped after a
// mid-loop failure.
type GrantResult struct {
	OK      []string         // services that succeeded
	Failed  map[string]error // service -> error for the call that failed
	Skipped []string         // services not attempted (after a failure)
}

// Err returns a multi-line error summarising a partial failure, or nil if
// every service succeeded.
func (r GrantResult) Err() error {
	if len(r.Failed) == 0 {
		return nil
	}
	var b strings.Builder
	for svc, e := range r.Failed {
		fmt.Fprintf(&b, "\n  failed: %s — %v", svc, e)
	}
	if len(r.OK) > 0 {
		fmt.Fprintf(&b, "\n  succeeded: %s", strings.Join(r.OK, ", "))
	}
	if len(r.Skipped) > 0 {
		fmt.Fprintf(&b, "\n  skipped: %s", strings.Join(r.Skipped, ", "))
	}
	return fmt.Errorf("%d service(s) failed:%s", len(r.Failed), b.String())
}

// AddGrants grants an agent access to one or more services. The backend's
// POST /api/agents/{id}/grants takes ONE service per call, and its
// CreateGrantRequest model REQUIRES both "agentId" and "serviceName" body
// fields (agentId has no default — omitting it returns HTTP 422). There is no
// bulk/array grant route, so we issue one request per service. On the first
// failure we stop and report which services succeeded and which were skipped.
func (c *Client) AddGrants(agentID string, services []string) GrantResult {
	res := GrantResult{Failed: map[string]error{}}
	for i, svc := range services {
		_, err := c.doRequest("POST", "/api/agents/"+agentID+"/grants",
			map[string]string{"agentId": agentID, "serviceName": svc}, nil)
		if err != nil {
			res.Failed[svc] = err
			res.Skipped = append(res.Skipped, services[i+1:]...)
			return res
		}
		res.OK = append(res.OK, svc)
	}
	return res
}

// RemoveGrants revokes an agent's access to one or more services. The backend
// revokes via path param: DELETE /api/agents/{id}/grants/{service_name} — one
// per call, no body — so we issue one request per service. On the first
// failure we stop and report which services succeeded and which were skipped.
func (c *Client) RemoveGrants(agentID string, services []string) GrantResult {
	res := GrantResult{Failed: map[string]error{}}
	for i, svc := range services {
		_, err := c.doRequest("DELETE",
			"/api/agents/"+agentID+"/grants/"+svc, nil, nil)
		if err != nil {
			res.Failed[svc] = err
			res.Skipped = append(res.Skipped, services[i+1:]...)
			return res
		}
		res.OK = append(res.OK, svc)
	}
	return res
}

// AgentIdentity validates the Client's agent key against the credentials
// endpoint. Replaces the PR #2 stub. GET /api/agents/credentials (no service
// query) returns {"grants":[...]} and carries NO agent name field, so a
// successful call just confirms the key is valid; we return the static label
// "agent" as the identity. Kept as (string, error) for internal/auth callers.
func (c *Client) AgentIdentity() (string, error) {
	if _, err := c.doRequest("GET", "/api/agents/credentials", nil, nil); err != nil {
		return "", err
	}
	return "agent", nil
}
