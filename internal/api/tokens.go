package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/c-lgrant/tvault/internal/clierr"
)

// Token is the list/show shape returned by the tokens endpoints.
//
// NOTE: the backend names the type field "tokenType" (not "type"), and stores
// editable metadata (displayName/description/tags) in a separate Firestore
// collection that is merged into the list/show responses.
//
// The CLI calls the free-text field "notes", but the backend's field is
// "description". It still reads a legacy "notes" value, but only when no
// description exists, so Notes decodes from description first (UnmarshalJSON).
type Token struct {
	ServiceName string   `json:"serviceName"`
	Type        string   `json:"tokenType"`
	Status      string   `json:"status"`
	DisplayName string   `json:"displayName,omitempty"`
	Notes       string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Labels      []string `json:"labels,omitempty"`
	// LabelsKnown is whether the response carried a "labels" field at all. The
	// control plane omits it when its metadata read failed, which is not the
	// same as "no labels": writing a label set computed from it would drop
	// the real ones.
	LabelsKnown bool `json:"-"`
	// Kind is "tv_signin" for a "Token Vault sign-in" credential (no stored
	// value); empty for an ordinary credential.
	Kind string `json:"kind,omitempty"`
}

// KindSignIn is the Token.Kind of a "Token Vault sign-in" credential.
const KindSignIn = "tv_signin"

// SignInLabel is how the CLI shows a sign-in credential's type.
const SignInLabel = "Token Vault sign-in"

// TypeLabel is the type shown by list/show: "Token Vault sign-in" for a
// sign-in credential, otherwise the stored token type.
func (t Token) TypeLabel() string {
	if t.Kind == KindSignIn {
		return SignInLabel
	}
	return t.Type
}

// CreateSignIn creates a "Token Vault sign-in" credential: a name with no
// stored value. Its MCP server is attached separately with PutMCPServers.
func (c *Client) CreateSignIn(service string) error {
	_, err := c.doRequest("POST", "/api/tokens/sign-in", map[string]any{"serviceName": service}, nil)
	return err
}

func (t *Token) UnmarshalJSON(b []byte) error {
	type plain Token // no methods: avoids recursing into this UnmarshalJSON
	var v struct {
		plain
		LegacyNotes string `json:"notes"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*t = Token(v.plain)
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(b, &probe); err == nil {
		_, t.LabelsKnown = probe["labels"]
		if string(probe["labels"]) == "null" {
			t.LabelsKnown = false
		}
	}
	if t.Notes == "" {
		t.Notes = v.LegacyNotes
	}
	return nil
}

// TokenMetadata is the editable-metadata payload for PATCH …/metadata.
// Pointer fields distinguish "not set" from "set to empty". Notes is sent as
// "description" (see Token).
type TokenMetadata struct {
	DisplayName *string   `json:"displayName,omitempty"`
	Notes       *string   `json:"description,omitempty"`
	Tags        *[]string `json:"tags,omitempty"`
}

// CreateTokenRequest is the CLI-facing shape for creating a token. It is
// translated into the backend's {serviceName, tokenData:{…}} envelope by
// CreateToken — the backend has no flat "credential"/"type" POST body.
type CreateTokenRequest struct {
	ServiceName string         `json:"serviceName"`
	Type        string         `json:"type"`
	Credential  string         `json:"credential,omitempty"`
	Extra       map[string]any `json:"-"`
}

func (c *Client) ListTokens() ([]Token, error) {
	body, err := c.doRequest("GET", "/api/tokens", nil, nil)
	if err != nil {
		return nil, err
	}
	var toks []Token
	if err := json.Unmarshal(body, &toks); err != nil {
		return nil, err
	}
	return toks, nil
}

func (c *Client) GetToken(service string) (*Token, error) {
	body, err := c.doRequest("GET", "/api/tokens/"+service, nil, nil)
	if err != nil {
		return nil, err
	}
	var t Token
	if err := json.Unmarshal(body, &t); err != nil {
		return nil, err
	}
	return &t, nil
}

// credentialFieldForType maps a backend tokenType to the tokenData key the
// backend reads the secret from (see backend/auth_utils.py enrich_* and the
// console token wizard). JWT, PlainText and RawCredential all carry their
// secret in accessToken; the rest use a type-specific field.
func credentialFieldForType(typ string) string {
	switch typ {
	case "SSHKey":
		return "sshPrivateKey"
	case "Certificate":
		return "certificateData"
	case "TOTP":
		return "totpSecret"
	default:
		return "accessToken"
	}
}

// GetTokenValue returns just the credential string for $(tvault tk get …).
//
// Routing depends on the client persona:
//   - Agent context (AgentKey set): GET /api/agents/credentials?service=X.
//     For webhook-mode vaults the backend issues a 307 to the user's webhook;
//     Go's HTTP client follows it transparently.
//   - Admin context (BearerToken set): the credential-ticket flow (POST
//     /api/vault/credential-ticket → GET <webhook>/v1/credential, bypassing
//     TV's backend on the credential leg). The webhook is the only vault
//     mode, so GET /api/tokens/{service} never carries a value; skipping it
//     saves a full round trip. The ticket route runs the same policies and
//     answers 409 SIGNIN_NO_VALUE for a sign-in credential.
func (c *Client) GetTokenValue(service string) (string, error) {
	// Agents and scoped keys (credentials:read) both read through the
	// agent-credentials endpoint.
	if c.AgentKey != "" || c.APIKey != "" {
		return c.getTokenValueAgent(service)
	}
	return c.getTokenValueZK(service)
}

// SignInNoValueError is the error for reading or changing the value of a
// "Token Vault sign-in" credential, which has none. It uses the same exit code
// as an empty credential (6) and carries the server's SIGNIN_NO_VALUE code.
func SignInNoValueError(service, request string) *clierr.CLIError {
	return &clierr.CLIError{
		Kind:    clierr.KindEmpty,
		Code:    "SIGNIN_NO_VALUE",
		Request: request,
		Message: service + " is a Token Vault sign-in credential: it has no value to read or change",
		Hint:    "agents use it through its MCP server; grant with `tvault grant <agent> " + service + "=mcp`. See `tvault explain SIGNIN_NO_VALUE`",
	}
}

// getTokenValueAgent is the agent-persona path. In platform mode the
// agent credentials endpoint returns {accessToken, serviceName, …}
// directly. In webhook mode it 307-redirects to the user's webhook at
// /v1/credential, which returns {"token": {accessToken, …}}; Go's
// HTTP client follows the redirect transparently, so we just need to
// handle both response shapes here.
func (c *Client) getTokenValueAgent(service string) (string, error) {
	body, err := c.doRequest("GET", "/api/agents/credentials", nil,
		map[string]string{"service": service})
	if err != nil {
		return "", err
	}
	if v := firstSecretField(body); v != "" {
		return v, nil
	}
	// Webhook-mode redirect lands here: response is {"token": {accessToken}}.
	var wrap struct {
		Token json.RawMessage `json:"token"`
	}
	if json.Unmarshal(body, &wrap) == nil && len(wrap.Token) > 0 {
		if v := firstSecretField(wrap.Token); v != "" {
			return v, nil
		}
	}
	return "", &clierr.CLIError{
		Kind:    clierr.KindEmpty,
		Request: "GET /api/agents/credentials",
		Message: "credential is empty (token has no value, or grant returned nothing)",
	}
}

// firstSecretField returns the first non-empty secret field from a token
// document, matching the priority used by the backend's get_primary_credential.
func firstSecretField(body []byte) string {
	var resp struct {
		AccessToken     string `json:"accessToken"`
		SSHPrivateKey   string `json:"sshPrivateKey"`
		CertificateData string `json:"certificateData"`
		TOTPSecret      string `json:"totpSecret"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}
	for _, v := range []string{
		resp.AccessToken, resp.SSHPrivateKey,
		resp.CertificateData, resp.TOTPSecret,
	} {
		if v != "" {
			return v
		}
	}
	return ""
}

// credentialTicketResp matches POST /api/vault/credential-ticket. The ticket
// is an HMAC over {userId, serviceName, purpose, exp} — no key material, no
// credential. The webhook verifies the ticket and serves the plaintext.
type credentialTicketResp struct {
	Ticket     string `json:"ticket"`
	WebhookURL string `json:"webhookUrl"`
	ExpiresIn  int    `json:"expiresIn"`
}

const (
	// DefaultWebhookTimeout bounds one webhook credential fetch.
	DefaultWebhookTimeout = 10 * time.Second
	// webhookAttempts: a webhook fetch that gets no response is tried once
	// more before the CLI exits, so a single stalled request does not leave
	// `$(tvault get …)` empty.
	webhookAttempts = 2
)

func (c *Client) webhookTimeout() time.Duration {
	if c.WebhookTimeout > 0 {
		return c.WebhookTimeout
	}
	return DefaultWebhookTimeout
}

// getTokenValueZK fetches a credential via the zero-knowledge ticket flow.
// Used as a fallback when GET /api/tokens/{service} returns no secret (the
// signal that the user is in webhook mode and TV has stripped secrets).
//
// A network failure on the webhook leg is retried with a NEW ticket: tickets
// are one-shot (the webhook records each nonce), so resending the old one
// would be rejected as a replay. Only network failures are retried; an HTTP
// error from the webhook is a real answer.
func (c *Client) getTokenValueZK(service string) (string, error) {
	var err error
	for attempt := 1; attempt <= webhookAttempts; attempt++ {
		var ticket credentialTicketResp
		if ticket, err = c.credentialTicket(service); err != nil {
			return "", err
		}
		var v string
		v, err = c.fetchWebhookCredential(ticket.WebhookURL, ticket.Ticket, service)
		var ce *clierr.CLIError
		if err == nil || !errors.As(err, &ce) || ce.Kind != clierr.KindNetwork {
			return v, err
		}
		if c.Debug && attempt < webhookAttempts {
			fmt.Fprintf(os.Stderr, "[debug] webhook attempt %d failed; retrying with a new ticket\n", attempt)
		}
	}
	return "", err
}

func (c *Client) credentialTicket(service string) (credentialTicketResp, error) {
	var ticket credentialTicketResp
	body, err := c.doRequest("POST", "/api/vault/credential-ticket",
		map[string]string{"serviceName": service, "purpose": "user_reveal"}, nil)
	if err != nil {
		return ticket, err
	}
	if err := json.Unmarshal(body, &ticket); err != nil {
		return ticket, &clierr.CLIError{
			Kind: clierr.KindServer, Request: "POST /api/vault/credential-ticket",
			Message: "could not parse ticket response: " + err.Error(),
		}
	}
	return ticket, nil
}

// fetchWebhookCredential makes the direct CLI → user-webhook call. Per the
// webhook spec (frontend/public/llm.txt), GET /v1/credential returns
// {"token": {accessToken, ...}}. We probe the same secret fields as the
// platform-mode path so output is identical regardless of vault mode.
func (c *Client) fetchWebhookCredential(webhookURL, ticket, service string) (string, error) {
	if webhookURL == "" || ticket == "" {
		return "", &clierr.CLIError{
			Kind: clierr.KindServer, Request: "GET <webhook>/v1/credential",
			Message: "backend returned empty webhook URL or ticket",
		}
	}
	reqLine := "GET " + webhookURL + "/v1/credential"
	if err := requireSecureWebhookURL(webhookURL, reqLine); err != nil {
		return "", err
	}
	u := webhookURL + "/v1/credential?ticket=" + url.QueryEscape(ticket) +
		"&service=" + url.QueryEscape(service)

	timeout := c.webhookTimeout()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return "", &clierr.CLIError{Kind: clierr.KindUser, Request: reqLine, Message: err.Error()}
	}

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	httpClient = withRedirectCheck(httpClient)
	start := time.Now()
	resp, err := httpClient.Do(req)
	if err != nil {
		// The *url.Error text carries the request URL, ticket included.
		err = stripURLQuery(err)
		if c.Debug {
			fmt.Fprintf(os.Stderr, "[debug] %s → connection error after %s: %v\n", reqLine, time.Since(start), err)
		}
		msg := "could not reach webhook — " + err.Error()
		if errors.Is(err, context.DeadlineExceeded) {
			msg = fmt.Sprintf("webhook did not respond within %s", timeout)
		}
		return "", &clierr.CLIError{Kind: clierr.KindNetwork, Request: reqLine, Message: msg}
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if c.Debug {
		fmt.Fprintf(os.Stderr, "[debug] %s → %d in %s (%d bytes)\n",
			reqLine, resp.StatusCode, time.Since(start), len(respBody))
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		er := parseErrorBody(respBody)
		if er.Message == "" {
			er.Message = string(respBody)
		}
		return "", &clierr.CLIError{
			Kind: kindForStatus(resp.StatusCode), Request: reqLine,
			Response: fmt.Sprintf("%d", resp.StatusCode), Message: er.Message,
		}
	}

	var out struct {
		Token json.RawMessage `json:"token"`
	}
	if err := json.Unmarshal(respBody, &out); err != nil || len(out.Token) == 0 {
		// Some webhooks may return the token doc at the top level instead
		// of nested under "token". Fall through and probe the raw body too.
		if v := firstSecretField(respBody); v != "" {
			return v, nil
		}
		return "", &clierr.CLIError{
			Kind: clierr.KindServer, Request: reqLine,
			Message: "webhook response did not contain a credential",
		}
	}
	if v := firstSecretField(out.Token); v != "" {
		return v, nil
	}
	return "", &clierr.CLIError{
		Kind: clierr.KindEmpty, Request: reqLine,
		Message: "webhook response did not contain a credential (token is empty)",
	}
}

// CreateToken stores a token. A credential value never goes to TV: it is
// sent straight to the user's webhook with a TV-signed store ticket
// (StoreTokenViaWebhook). Only an empty placeholder, which carries no
// secret, goes through POST /api/tokens with its {serviceName, tokenData}
// envelope.
func (c *Client) CreateToken(req CreateTokenRequest) error {
	if req.Credential != "" {
		// "create": a name that already exists is refused, never replaced.
		return c.storeViaTicket(req.ServiceName, req.Type, req.Credential, req.Extra, storeIntentCreate)
	}
	tokenData := map[string]any{}
	if req.Type != "" {
		tokenData["tokenType"] = req.Type
	}
	for k, v := range req.Extra {
		tokenData[k] = v
	}
	payload := map[string]any{
		"serviceName": req.ServiceName,
		"tokenData":   tokenData,
	}
	_, err := c.doRequest("POST", "/api/tokens", payload, nil)
	return err
}

// SetTokenValue rotates the credential value through the store-ticket flow,
// so the new value goes straight to the user's webhook and never to TV.
// The webhook replaces the whole document, so the token's current type is
// read first (metadata only, no secret) and sent again: an SSH key or TOTP
// secret then lands in its own field and keeps its type. If the read fails,
// the value is stored as PlainText.
func (c *Client) SetTokenValue(service, credential string) error {
	typ := "PlainText"
	if t, err := c.GetToken(service); err == nil {
		if t.Kind == KindSignIn {
			return SignInNoValueError(service, "GET /api/tokens/"+service)
		}
		if t.Type != "" {
			typ = t.Type
		}
	}
	return c.StoreTokenViaWebhook(service, typ, credential)
}

// StoreTokenViaWebhook is the webhook-mode equivalent of CreateToken /
// SetTokenValue: it fetches a signed store ticket from TV, then POSTs the
// token document directly to the user's webhook at /v1/store. The secret
// never traverses TV's backend.
func (c *Client) StoreTokenViaWebhook(service, tokenType, credential string) error {
	return c.storeViaTicket(service, tokenType, credential, nil, "")
}

// storeViaTicket sends the value to the webhook with a TV-signed ticket.
// intent is storeIntentCreate for a new credential, or "" to create or replace.
func (c *Client) storeViaTicket(service, tokenType, credential string, extra map[string]any, intent string) error {
	if c.DryRun {
		out := c.DryRunOut
		if out == nil {
			out = os.Stderr
		}
		if intent != "" {
			fmt.Fprintf(out, "[dry-run] POST /api/vault/store-ticket {serviceName: %q, intent: %q}\n", service, intent)
		} else {
			fmt.Fprintf(out, "[dry-run] POST /api/vault/store-ticket {serviceName: %q}\n", service)
		}
		fmt.Fprintf(out, "[dry-run] POST <webhook>/v1/store (%s, value redacted)\n", credentialFieldForType(tokenType))
		return nil
	}
	ticket, err := c.vaultStoreTicket(service, intent)
	if err != nil {
		return err
	}
	tokenData := map[string]any{}
	for k, v := range extra {
		tokenData[k] = v
	}
	tokenData["tokenType"] = tokenType
	tokenData[credentialFieldForType(tokenType)] = credential
	payload := map[string]any{
		"ticket":    ticket.Ticket,
		"service":   service,
		"tokenData": tokenData,
	}
	return c.postWebhookStore(ticket.WebhookURL, payload)
}

func (c *Client) postWebhookStore(webhookURL string, payload any) error {
	if webhookURL == "" {
		return &clierr.CLIError{
			Kind: clierr.KindServer, Request: "POST <webhook>/v1/store",
			Message: "backend returned empty webhook URL",
		}
	}
	reqLine := "POST " + webhookURL + "/v1/store"
	if err := requireSecureWebhookURL(webhookURL, reqLine); err != nil {
		return err
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return &clierr.CLIError{Kind: clierr.KindUser, Request: reqLine, Message: err.Error()}
	}
	req, err := http.NewRequest("POST", webhookURL+"/v1/store", bytes.NewReader(raw))
	if err != nil {
		return &clierr.CLIError{Kind: clierr.KindUser, Request: reqLine, Message: err.Error()}
	}
	req.Header.Set("Content-Type", "application/json")

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	httpClient = withRedirectCheck(httpClient)
	start := time.Now()
	resp, err := httpClient.Do(req)
	if err != nil {
		err = stripURLQuery(err)
		if c.Debug {
			fmt.Fprintf(os.Stderr, "[debug] %s → connection error after %s: %v\n", reqLine, time.Since(start), err)
		}
		return &clierr.CLIError{
			Kind: clierr.KindNetwork, Request: reqLine,
			Message: "could not reach webhook — " + err.Error(),
		}
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if c.Debug {
		fmt.Fprintf(os.Stderr, "[debug] %s → %d in %s (%d bytes)\n",
			reqLine, resp.StatusCode, time.Since(start), len(body))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		er := parseErrorBody(body)
		if er.Message == "" {
			er.Message = string(body)
		}
		kind := kindForStatus(resp.StatusCode)
		if resp.StatusCode == 401 {
			// A 401 from the webhook means the store ticket was refused
			// (ticket_invalid / ticket_expired), not that the CLI login is
			// bad: logging in again would not help, so it is a server error.
			kind = clierr.KindServer
		}
		return &clierr.CLIError{
			Kind: kind, Request: reqLine,
			Response: fmt.Sprintf("%d", resp.StatusCode), Message: er.Message,
		}
	}
	return nil
}

// UpdateTokenMetadata edits displayName/notes/tags (PATCH …/metadata).
func (c *Client) UpdateTokenMetadata(service string, md TokenMetadata) error {
	_, err := c.doRequest("PATCH", "/api/tokens/"+service+"/metadata", md, nil)
	return err
}

// DeleteTokens removes one (single endpoint) or many (bulk endpoint) tokens.
// The bulk endpoint expects the field name "serviceNames".
func (c *Client) DeleteTokens(services []string) error {
	if len(services) == 1 {
		_, err := c.doRequest("DELETE", "/api/tokens/"+services[0], nil, nil)
		return err
	}
	_, err := c.doRequest("DELETE", "/api/tokens/bulk",
		map[string][]string{"serviceNames": services}, nil)
	return err
}

func (c *Client) RefreshToken_OAuth(service string) error {
	_, err := c.doRequest("POST", "/api/tokens/"+service+"/refresh", nil, nil)
	return err
}

// TokenHistory returns a token's usage history. The backend has no dedicated
// .../history route; per-service history is the audit log filtered by
// serviceName (GET /api/tokens/audit-log?serviceName=…), which returns an
// {events, pagination} envelope.
func (c *Client) TokenHistory(service string) ([]map[string]any, error) {
	body, err := c.doRequest("GET", "/api/tokens/audit-log", nil,
		map[string]string{"serviceName": service})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Events []map[string]any `json:"events"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	return resp.Events, nil
}
