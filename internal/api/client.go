// Package api is the typed HTTP client for the Token Vault backend. client.go
// holds the transport core: request building, auth headers, status→error
// mapping, timeouts, and GET retry with exponential backoff.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/c-lgrant/tvault/internal/clierr"
)

// GET retry policy: up to maxGetAttempts attempts. Between attempts the client
// sleeps the server's Retry-After when given (429), else an exponential
// backoff with jitter. A Retry-After beyond maxRetryWait fails immediately —
// a CLI must not block for minutes; the caller sees exit code 7 and the hint.
const (
	maxGetAttempts = 3
	baseBackoff    = 500 * time.Millisecond
	maxRetryWait   = 10 * time.Second
)

// DefaultUserAgent is sent as the User-Agent header on every request.
// Set this at program startup before any Client is created.
var DefaultUserAgent = "tvault"

// Client talks to one Token Vault API base URL with one set of credentials.
// Exactly one of BearerToken (admin), AgentKey (agent) or APIKey (scoped key)
// is set; all three are sent as Authorization: Bearer.
type Client struct {
	BaseURL     string
	HTTP        *http.Client
	BearerToken string // admin: Firebase ID token
	AgentKey    string // agent: tvagent_*
	APIKey      string // key: tvkey_* scoped key
	UserAgent   string // sent as User-Agent; defaults to DefaultUserAgent when New() is used
	Debug       bool

	DryRun    bool      // when true, mutating requests are printed, not sent
	DryRunOut io.Writer // where dry-run output goes; defaults to os.Stderr

	sleep func(time.Duration) // retry-backoff sleeper; nil = time.Sleep (tests stub it)
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
		BaseURL:   baseURL,
		UserAgent: DefaultUserAgent,
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
	Code         string
	Message      string
	MissingScope string
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
		Code         string  `json:"code"`
		Message      string  `json:"message"`
		MissingScope *string `json:"missingScope"`
	}
	if err := json.Unmarshal(probe.Detail, &obj); err == nil {
		er := errorResponse{Code: obj.Code, Message: obj.Message}
		if obj.MissingScope != nil {
			er.MissingScope = *obj.MissingScope
		}
		return er
	}
	return errorResponse{Message: string(probe.Detail)}
}

// kindForError maps a response to a Kind. The scoped-key error codes win over
// the plain status mapping so scripts can tell "missing scope" from "bad
// request" by exit code alone.
func kindForError(status int, code string) clierr.Kind {
	switch code {
	case "SCOPE_DENIED":
		return clierr.KindScopeDenied
	case "HUMAN_ONLY":
		return clierr.KindHumanOnly
	case "KEY_EXPIRED":
		return clierr.KindKeyExpired
	case "KEY_SUSPENDED":
		return clierr.KindKeySuspended
	case "INVALID_KEY":
		return clierr.KindInvalidKey
	case "VAULT_LOCKED":
		return clierr.KindVaultLocked
	}
	return kindForStatus(status)
}

func kindForStatus(status int) clierr.Kind {
	switch {
	case status == 423:
		return clierr.KindVaultLocked
	case status == 429:
		return clierr.KindRateLimited
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
// Connection errors and 429s are retried with backoff, but only for GET:
// retrying a POST (e.g. /api/cli/auth/exchange) after a lost response can
// burn a single-use code the server already processed.
func (c *Client) doRequest(method, path string, body any, query map[string]string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < maxGetAttempts; attempt++ {
		respBody, retriable, err := c.attempt(method, path, body, query)
		if err == nil {
			return respBody, nil
		}
		lastErr = err
		if !retriable || method != http.MethodGet || attempt == maxGetAttempts-1 {
			return nil, err
		}
		delay, ok := backoffDelay(attempt, err)
		if !ok {
			return nil, err
		}
		if c.sleep != nil {
			c.sleep(delay)
		} else {
			time.Sleep(delay)
		}
	}
	return nil, lastErr
}

// backoffDelay picks the pause before retry attempt+1. The server's
// Retry-After wins when present; past maxRetryWait the second return is
// false and the caller gives up rather than blocking. Without a server
// hint: exponential base doubling per attempt plus 0–50% jitter.
func backoffDelay(attempt int, err error) (time.Duration, bool) {
	var ce *clierr.CLIError
	if errors.As(err, &ce) && ce.RetryAfter > 0 {
		if ce.RetryAfter > maxRetryWait {
			return 0, false
		}
		return ce.RetryAfter, true
	}
	d := baseBackoff << attempt
	return d + time.Duration(rand.Int63n(int64(d/2)+1)), true
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
	// Admin ID tokens, tvkey_* keys and tvagent_* keys all travel as a Bearer
	// token; the server tells them apart by prefix.
	switch {
	case c.BearerToken != "":
		req.Header.Set("Authorization", "Bearer "+c.BearerToken)
	case c.APIKey != "":
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	case c.AgentKey != "":
		req.Header.Set("Authorization", "Bearer "+c.AgentKey)
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
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
	cliErr := &clierr.CLIError{
		Kind:     kindForError(resp.StatusCode, er.Code),
		Code:     er.Code,
		Scope:    er.MissingScope,
		Request:  reqLine,
		Response: respSummary,
		Message:  er.Message,
	}
	switch cliErr.Kind {
	case clierr.KindScopeDenied:
		if er.MissingScope != "" {
			cliErr.Message = fmt.Sprintf("missing scope %q — %s", er.MissingScope, er.Message)
			cliErr.Hint = fmt.Sprintf("use a key that carries %s (tvault keys create --scopes %s)", er.MissingScope, er.MissingScope)
		} else if er.Message == "" {
			cliErr.Message = "this key lacks a required scope"
		}
	case clierr.KindHumanOnly:
		cliErr.Hint = "this operation needs a signed-in human — run `tvault login` and switch to the admin context"
	case clierr.KindKeyExpired:
		cliErr.Hint = "rotate the key (tvault keys rotate / tvault agents rotate-key) or log in with a new one"
	case clierr.KindKeySuspended:
		cliErr.Hint = "the key is suspended — ask the owner to resume it, or use another key"
	case clierr.KindInvalidKey:
		cliErr.Hint = "the key is unknown or was revoked — check it, or log in with a valid key (tvault login --key)"
	}
	// Code-specific guidance for codes that keep their status-derived Kind
	// (and so their exit code: 1 for 4xx, 2 for 401).
	if cliErr.Hint == "" {
		switch er.Code {
		case "REAUTH_REQUIRED":
			cliErr.Kind = clierr.KindAuth
			cliErr.Hint = "this action needs a fresh sign-in — run `tvault login` again, then retry"
		case "NOT_OWNER":
			cliErr.Hint = "only the owner of this key/agent can do that"
		case "GRANT_REQUIRED":
			cliErr.Hint = "the principal creating this must already hold the grant — grant it first (tvault keys grant <key> <service>)"
		case "NO_GRANT":
			cliErr.Hint = "this principal has no grant for that service — ask the owner to grant it (`tvault grant <agent> <service>` or `tvault keys grant <key> <service>`)"
		case "SCOPE_NOT_DELEGABLE":
			cliErr.Hint = "only a signed-in human can give that scope — create the key or agent from the console or an admin context"
		case "SELF_CHANGE_FORBIDDEN":
			cliErr.Hint = "a key or agent can't loosen its own controls — ask the account owner to make this change"
		case "ROTATION_CONFLICT":
			cliErr.Hint = "another rotation of this key won the race — use the key it returned, or rotate again"
		case "UNKNOWN_SCOPE":
			cliErr.Hint = "see the scope list in the README (Keys section)"
		case "INVALID_EXPIRY":
			cliErr.Hint = "use --expires 30d|90d|365d|YYYY-MM-DD|never (must be in the future)"
		}
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs > 0 {
			cliErr.RetryAfter = time.Duration(secs) * time.Second
			cliErr.Hint = fmt.Sprintf("rate limited — retry in %ds", secs)
		} else {
			cliErr.Hint = "rate limited — back off before retrying"
		}
		return nil, true, cliErr
	}
	return nil, false, cliErr
}
