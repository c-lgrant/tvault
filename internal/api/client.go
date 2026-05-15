// Package api is the typed HTTP client for the Token Vault backend. client.go
// holds the transport core: request building, auth headers, status→error
// mapping, timeouts, and the one connection-error retry.
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/c-lgrant/tvault/internal/clierr"
)

// Client talks to one Token Vault API base URL with one set of credentials.
// Exactly one of BearerToken (admin) or AgentKey (agent) is set.
type Client struct {
	BaseURL     string
	HTTP        *http.Client
	BearerToken string // admin: Firebase ID token → Authorization: Bearer
	AgentKey    string // agent: tvagent_* → X-Agent-Key
	Debug       bool

	DryRun    bool      // when true, mutating requests are printed, not sent
	DryRunOut io.Writer // where dry-run output goes; defaults to os.Stderr
}

// New builds a Client with sensible timeouts. timeout overrides the default
// when > 0; the TVAULT_TIMEOUT env var overrides that.
func New(baseURL string, timeout time.Duration) *Client {
	if env := os.Getenv("TVAULT_TIMEOUT"); env != "" {
		if secs, err := strconv.Atoi(env); err == nil {
			timeout = time.Duration(secs) * time.Second
		}
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Client{
		BaseURL: baseURL,
		HTTP: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				IdleConnTimeout:     30 * time.Second,
				TLSHandshakeTimeout: 10 * time.Second,
				DialContext: (&net.Dialer{
					Timeout: 10 * time.Second,
				}).DialContext,
			},
		},
	}
}

// errorResponse is the backend's standard error envelope. The wire-level
// "detail" field is either a string or an object {code, message}; it is
// decoded procedurally in parseErrorBody.
type errorResponse struct {
	Code    string
	Message string
}

func parseErrorBody(body []byte) errorResponse {
	var probe struct {
		Detail json.RawMessage `json:"detail"`
	}
	if err := json.Unmarshal(body, &probe); err != nil || len(probe.Detail) == 0 {
		return errorResponse{Message: string(body)}
	}
	// detail may be a bare string …
	var s string
	if err := json.Unmarshal(probe.Detail, &s); err == nil {
		return errorResponse{Message: s}
	}
	// … or an object {code, message}
	var obj struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(probe.Detail, &obj); err == nil {
		return errorResponse{Code: obj.Code, Message: obj.Message}
	}
	return errorResponse{Message: string(probe.Detail)}
}

func kindForStatus(status int) clierr.Kind {
	switch {
	case status == 423:
		return clierr.KindVaultLocked
	case status == 401:
		return clierr.KindAuth
	case status >= 500:
		return clierr.KindServer
	default: // 400, 403, 404, 409, 422 …
		return clierr.KindUser
	}
}

// doRequest issues one HTTP request, JSON-encoding body when non-nil, and
// returns the raw response body on 2xx. Non-2xx becomes a *clierr.CLIError
// carrying the mapped Kind, the request line, and the response summary.
// Connection errors are retried once, but only for GET: retrying a POST
// (e.g. /api/cli/auth/exchange) after a lost response can burn a
// single-use code the server already processed.
func (c *Client) doRequest(method, path string, body any, query map[string]string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		respBody, retriable, err := c.attempt(method, path, body, query)
		if err == nil {
			return respBody, nil
		}
		lastErr = err
		if !retriable || method != http.MethodGet {
			return nil, err
		}
	}
	return nil, lastErr
}

func (c *Client) attempt(method, path string, body any, query map[string]string) ([]byte, bool, error) {
	reqLine := method + " " + path

	// In dry-run mode, mutating requests are printed and never sent. Reads
	// (GET) still go through so commands that fetch then mutate still work.
	isMutation := method == http.MethodPost || method == http.MethodPut ||
		method == http.MethodPatch || method == http.MethodDelete
	if c.DryRun && isMutation {
		out := c.DryRunOut
		if out == nil {
			out = os.Stderr
		}
		fmt.Fprintf(out, "[dry-run] %s\n", reqLine)
		if body != nil {
			pretty, _ := json.MarshalIndent(body, "[dry-run]   ", "  ")
			fmt.Fprintf(out, "[dry-run]   body: %s\n", pretty)
		}
		return []byte("{}"), false, nil
	}

	var bodyReader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, false, &clierr.CLIError{Kind: clierr.KindUser, Request: reqLine, Message: "encoding request body: " + err.Error()}
		}
		bodyReader = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, bodyReader)
	if err != nil {
		return nil, false, &clierr.CLIError{Kind: clierr.KindUser, Request: reqLine, Message: err.Error()}
	}
	if len(query) > 0 {
		q := req.URL.Query()
		for k, v := range query {
			q.Set(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	}
	if c.AgentKey != "" {
		req.Header.Set("X-Agent-Key", c.AgentKey)
	}

	start := time.Now()
	httpClient := c.HTTP
	if httpClient == nil {
		// Clients built directly (e.g. in tests) may omit HTTP; fall back to
		// a sane default rather than nil-panicking.
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		if c.Debug {
			fmt.Fprintf(os.Stderr, "[debug] %s → connection error after %s: %v\n", reqLine, time.Since(start), err)
		}
		// Connection-level failures are retriable network errors.
		return nil, true, &clierr.CLIError{
			Kind:    clierr.KindNetwork,
			Request: reqLine,
			Message: "could not reach " + c.BaseURL + " — " + err.Error(),
		}
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if c.Debug {
		fmt.Fprintf(os.Stderr, "[debug] %s → %d in %s (%d bytes)\n", reqLine, resp.StatusCode, time.Since(start), len(respBody))
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return respBody, false, nil
	}

	er := parseErrorBody(respBody)
	respSummary := strconv.Itoa(resp.StatusCode)
	if er.Code != "" {
		respSummary += " " + er.Code
	}
	if er.Message != "" {
		respSummary += " — " + er.Message
	}
	return nil, false, &clierr.CLIError{
		Kind:     kindForStatus(resp.StatusCode),
		Request:  reqLine,
		Response: respSummary,
		Message:  er.Message,
	}
}
