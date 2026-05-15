package api

import "encoding/json"

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
// GET /api/tokens/{service} returns the full token document; the secret lives
// in one of several fields depending on token type. We probe the known ones
// in priority order.
func (c *Client) GetTokenValue(service string) (string, error) {
	body, err := c.doRequest("GET", "/api/tokens/"+service, nil, nil)
	if err != nil {
		return "", err
	}
	var resp struct {
		AccessToken     string `json:"accessToken"`
		SSHPrivateKey   string `json:"sshPrivateKey"`
		CertificateData string `json:"certificateData"`
		TOTPSecret      string `json:"totpSecret"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", err
	}
	for _, v := range []string{
		resp.AccessToken, resp.SSHPrivateKey,
		resp.CertificateData, resp.TOTPSecret,
	} {
		if v != "" {
			return v, nil
		}
	}
	return "", nil
}

// CreateToken stores a token via POST /api/tokens. The backend expects a
// {serviceName, tokenData:{…}} envelope, where tokenData carries the type in
// tokenType and the secret in a type-specific field (accessToken for bearer
// types, sshPrivateKey/certificateData/totpSecret for the rest — see
// credentialFieldForType). POST is an upsert, so it doubles as the rotate
// path (see SetTokenValue).
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
	return err
}

// SetTokenValue rotates the credential value. The backend has no PUT route —
// POST /api/tokens is an upsert keyed on serviceName — so we reuse it.
func (c *Client) SetTokenValue(service, credential string) error {
	payload := map[string]any{
		"serviceName": service,
		"tokenData":   map[string]any{"accessToken": credential},
	}
	_, err := c.doRequest("POST", "/api/tokens", payload, nil)
	return err
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
