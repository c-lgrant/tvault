package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/c-lgrant/tvault/internal/clierr"
)

// Token is the list/show shape returned by the tokens endpoints.
//
// NOTE: the backend names the type field "tokenType" (not "type"), and stores
// editable metadata (displayName/notes/tags) in a separate Firestore
// collection that is merged into the list/show responses.
type Token struct {
	ServiceName string   `json:"serviceName"`
	Type        string   `json:"tokenType"`
	Status      string   `json:"status"`
	DisplayName string   `json:"displayName,omitempty"`
	Notes       string   `json:"notes,omitempty"`
	Tags        []string `json:"tags,omitempty"`
}

// TokenMetadata is the editable-metadata payload for PATCH …/metadata.
// Pointer fields distinguish "not set" from "set to empty".
type TokenMetadata struct {
	DisplayName *string   `json:"displayName,omitempty"`
	Notes       *string   `json:"notes,omitempty"`
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
//   - Admin context (BearerToken set): GET /api/tokens/{service}. The
//     response carries the secret in one of several type-specific fields.
//     In webhook mode the backend strips those (TV never holds plaintext),
//     and we fall back to the credential-ticket flow (POST
//     /api/vault/credential-ticket → GET <webhook>/v1/credential, bypassing
//     TV's backend on the credential leg).
func (c *Client) GetTokenValue(service string) (string, error) {
	if c.AgentKey != "" {
		return c.getTokenValueAgent(service)
	}
	body, err := c.doRequest("GET", "/api/tokens/"+service, nil, nil)
	if err != nil {
		return "", err
	}
	if v := firstSecretField(body); v != "" {
		return v, nil
	}
	return c.getTokenValueZK(service)
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

// getTokenValueZK fetches a credential via the zero-knowledge ticket flow.
// Used as a fallback when GET /api/tokens/{service} returns no secret (the
// signal that the user is in webhook mode and TV has stripped secrets).
func (c *Client) getTokenValueZK(service string) (string, error) {
	body, err := c.doRequest("POST", "/api/vault/credential-ticket",
		map[string]string{"serviceName": service, "purpose": "user_reveal"}, nil)
	if err != nil {
		return "", err
	}
	var ticket credentialTicketResp
	if err := json.Unmarshal(body, &ticket); err != nil {
		return "", &clierr.CLIError{
			Kind: clierr.KindServer, Request: "POST /api/vault/credential-ticket",
			Message: "could not parse ticket response: " + err.Error(),
		}
	}
	return c.fetchWebhookCredential(ticket.WebhookURL, ticket.Ticket, service)
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
	u := webhookURL + "/v1/credential?ticket=" + url.QueryEscape(ticket) +
		"&service=" + url.QueryEscape(service)
	reqLine := "GET " + webhookURL + "/v1/credential"

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", &clierr.CLIError{Kind: clierr.KindUser, Request: reqLine, Message: err.Error()}
	}

	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	start := time.Now()
	resp, err := httpClient.Do(req)
	if err != nil {
		if c.Debug {
			fmt.Fprintf(os.Stderr, "[debug] %s → connection error after %s: %v\n", reqLine, time.Since(start), err)
		}
		return "", &clierr.CLIError{
			Kind: clierr.KindNetwork, Request: reqLine,
			Message: "could not reach webhook — " + err.Error(),
		}
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

// CreateToken stores a token via POST /api/tokens. The backend expects a
// {serviceName, tokenData:{…}} envelope, where tokenData carries the type in
// tokenType and the secret in a type-specific field (accessToken for bearer
// types, sshPrivateKey/certificateData/totpSecret for the rest — see
// credentialFieldForType). POST is an upsert, so it doubles as the rotate
// path (see SetTokenValue).
//
// In webhook (zero-knowledge) mode, if a credential is provided, the
// backend rejects the POST and we fall back to the store-ticket flow so
// the secret bypasses TV entirely. Empty-credential placeholders still
// go through the standard path — they carry no secret.
func (c *Client) CreateToken(req CreateTokenRequest) error {
	tokenData := map[string]any{}
	if req.Type != "" {
		tokenData["tokenType"] = req.Type
	}
	if req.Credential != "" {
		tokenData[credentialFieldForType(req.Type)] = req.Credential
	}
	for k, v := range req.Extra {
		tokenData[k] = v
	}
	payload := map[string]any{
		"serviceName": req.ServiceName,
		"tokenData":   tokenData,
	}
	_, err := c.doRequest("POST", "/api/tokens", payload, nil)
	if isWebhookModeReject(err) && req.Credential != "" {
		return c.StoreTokenViaWebhook(req.ServiceName, req.Type, req.Credential)
	}
	return err
}

// SetTokenValue rotates the credential value. The backend has no PUT route —
// POST /api/tokens is an upsert keyed on serviceName — so we reuse it.
//
// In webhook (zero-knowledge) mode the backend rejects plaintext POSTs to
// /api/tokens (the secret would otherwise transit TV). We detect that
// rejection and transparently fall back to the store-ticket flow, which
// pushes the credential directly to the user's webhook. The caller never
// has to think about vault mode.
func (c *Client) SetTokenValue(service, credential string) error {
	payload := map[string]any{
		"serviceName": service,
		"tokenData":   map[string]any{"accessToken": credential},
	}
	_, err := c.doRequest("POST", "/api/tokens", payload, nil)
	if isWebhookModeReject(err) {
		// Empty tokenType: don't overwrite the existing token's type — set
		// semantics rotate the value only.
		return c.StoreTokenViaWebhook(service, "", credential)
	}
	return err
}

// isWebhookModeReject identifies the backend's "Webhook mode: plaintext
// secrets must not transit Token Vault" 400 so callers can recover via the
// store-ticket flow. Pattern-matches on the message because the backend
// returns no machine-readable code for this case.
func isWebhookModeReject(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "Webhook mode") &&
		strings.Contains(msg, "must not transit")
}

// StoreTokenViaWebhook is the webhook-mode equivalent of CreateToken /
// SetTokenValue: it fetches a signed store ticket from TV, then POSTs the
// token document directly to the user's webhook at /v1/store. The secret
// never traverses TV's backend.
func (c *Client) StoreTokenViaWebhook(service, tokenType, credential string) error {
	ticket, err := c.VaultStoreTicket(service)
	if err != nil {
		return err
	}
	tokenData := map[string]any{
		"tokenType":                       tokenType,
		credentialFieldForType(tokenType): credential,
	}
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
	start := time.Now()
	resp, err := httpClient.Do(req)
	if err != nil {
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
		return &clierr.CLIError{
			Kind: kindForStatus(resp.StatusCode), Request: reqLine,
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
