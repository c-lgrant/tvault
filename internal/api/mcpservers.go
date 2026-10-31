package api

import (
	"encoding/json"
	"net/url"
	"strconv"
)

// MCPServer is one MCP server attached to a credential. Headers are header
// templates: the literal placeholder ${TOKEN} marks where the user's webhook
// injects the credential. No credential value is ever part of this shape.
//
// A key or agent reading a credential's servers sees only the URL origin
// (URLRedacted is then true) and no headers.
type MCPServer struct {
	Name        string            `json:"name"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Template    string            `json:"template,omitempty"`
	URLRedacted bool              `json:"urlRedacted,omitempty"`
	Tools       *MCPToolsSummary  `json:"tools,omitempty"`
}

// MCPToolsSummary is the cached tool list's summary (count, never the tools).
type MCPToolsSummary struct {
	Count     int    `json:"count"`
	FetchedAt string `json:"fetchedAt,omitempty"`
	Error     string `json:"error,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	Stale     bool   `json:"stale,omitempty"`
}

// String renders the summary for a table cell: "12", "12 (stale)", "pending",
// or the last fetch's error code.
func (t *MCPToolsSummary) String() string {
	if t == nil {
		return ""
	}
	if t.Error != "" {
		return t.Error
	}
	if t.FetchedAt == "" {
		return "pending"
	}
	s := strconv.Itoa(t.Count)
	if t.Truncated {
		s += "+"
	}
	if t.Stale {
		s += " (stale)"
	}
	return s
}

// MCPTemplate is a preset from GET /api/config/mcp-templates.
type MCPTemplate struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	DocsURL string            `json:"docsUrl,omitempty"`
}

type mcpServersBody struct {
	Servers []MCPServer `json:"servers"`
}

// ListMCPServers returns the MCP servers attached to a credential.
func (c *Client) ListMCPServers(service string) ([]MCPServer, error) {
	body, err := c.doRequest("GET", "/api/tokens/"+url.PathEscape(service)+"/mcp-servers", nil, nil)
	if err != nil {
		return nil, err
	}
	var res mcpServersBody
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	return res.Servers, nil
}

// PutMCPServers replaces a credential's MCP servers with servers (a full
// replace: an empty list clears them) and returns the list as stored.
// A nil slice is sent as [] so the server never reads it as "missing".
func (c *Client) PutMCPServers(service string, servers []MCPServer) ([]MCPServer, error) {
	if servers == nil {
		servers = []MCPServer{}
	}
	for i := range servers {
		if servers[i].Headers == nil {
			servers[i].Headers = map[string]string{}
		}
		servers[i].URLRedacted = false // read-only view fields, never sent back
		servers[i].Tools = nil
	}
	body, err := c.doRequest("PUT", "/api/tokens/"+url.PathEscape(service)+"/mcp-servers",
		mcpServersBody{Servers: servers}, nil)
	if err != nil {
		return nil, err
	}
	var res mcpServersBody
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	return res.Servers, nil
}

// ListMCPTemplates returns the server presets (public endpoint).
func (c *Client) ListMCPTemplates() ([]MCPTemplate, error) {
	body, err := c.doRequest("GET", "/api/config/mcp-templates", nil, nil)
	if err != nil {
		return nil, err
	}
	var res struct {
		Templates []MCPTemplate `json:"templates"`
	}
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	return res.Templates, nil
}
