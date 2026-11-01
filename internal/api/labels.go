package api

import (
	"encoding/json"
	"net/url"
)

// LabelSummary is one row of GET /api/labels: how many credentials, agents
// and keys carry the label, and the policies attached to it.
type LabelSummary struct {
	Label       string   `json:"label"`
	Credentials int      `json:"credentials"`
	Agents      int      `json:"agents"`
	Keys        int      `json:"keys"`
	PolicyIDs   []string `json:"policyIds"`
}

// LabelPolicy is a policy that applies to an object through one of its labels.
type LabelPolicy struct {
	ID      string  `json:"id"`
	Label   string  `json:"label"`
	Enabled bool    `json:"enabled"`
	Name    *string `json:"name,omitempty"`
}

// PutLabelsResult is the PUT /api/labels/{kind}/{id} response.
type PutLabelsResult struct {
	EntityType string        `json:"entityType"`
	EntityID   string        `json:"entityId"`
	Labels     []string      `json:"labels"`
	Policies   []LabelPolicy `json:"policies"`
}

// ListLabels returns every label in use, with counts and attached policy IDs.
// The raw body is returned too so `--json` can print it unchanged.
func (c *Client) ListLabels() ([]LabelSummary, []byte, error) {
	body, err := c.doRequest("GET", "/api/labels", nil, nil)
	if err != nil {
		return nil, nil, err
	}
	var res struct {
		Labels []LabelSummary `json:"labels"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, nil, err
	}
	return res.Labels, body, nil
}

// PutLabels replaces the label set on one object. kind is the wire entity type:
// credential, agent or api_key. Removing a label that has policies attached
// needs policies:write (SCOPE_DENIED otherwise).
func (c *Client) PutLabels(kind, id string, labels []string) (*PutLabelsResult, error) {
	if labels == nil {
		labels = []string{}
	}
	body, err := c.doRequest("PUT", "/api/labels/"+url.PathEscape(kind)+"/"+url.PathEscape(id),
		map[string]any{"labels": labels}, nil)
	if err != nil {
		return nil, err
	}
	var res PutLabelsResult
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// PolicyAttachment names one object (or label) a policy applies to.
type PolicyAttachment struct {
	EntityType string `json:"entityType"`
	EntityID   string `json:"entityId"`
}

// AttachPolicy attaches a policy to the given entities.
func (c *Client) AttachPolicy(policyID string, atts []PolicyAttachment) error {
	return c.policyAttachment("attach", policyID, atts)
}

// DetachPolicy detaches a policy from the given entities. The server requires
// a signed-in human for policies that protect a credential's channels.
func (c *Client) DetachPolicy(policyID string, atts []PolicyAttachment) error {
	return c.policyAttachment("detach", policyID, atts)
}

func (c *Client) policyAttachment(verb, policyID string, atts []PolicyAttachment) error {
	_, err := c.doRequest("POST", "/api/policies/"+url.PathEscape(policyID)+"/"+verb,
		map[string]any{"attachments": atts}, nil)
	return err
}

// CurrentLabels reads an object's label set from the list endpoint that
// includes it. found is false when no such object is listed.
func (c *Client) CurrentLabels(kind, id string) (labels []string, found bool, err error) {
	switch kind {
	case "credential":
		toks, err := c.ListTokens()
		if err != nil {
			return nil, false, err
		}
		for _, t := range toks {
			if t.ServiceName == id {
				return t.Labels, true, nil
			}
		}
	case "agent":
		agents, err := c.ListAgents()
		if err != nil {
			return nil, false, err
		}
		for _, a := range agents {
			if a.ID == id {
				return a.Labels, true, nil
			}
		}
	case "api_key":
		keys, err := c.ListKeys()
		if err != nil {
			return nil, false, err
		}
		for _, k := range keys {
			if k.ID == id {
				return k.Labels, true, nil
			}
		}
	}
	return nil, false, nil
}
