package api

import "encoding/json"

// ExchangeResult is the payload of POST /api/cli/auth/exchange.
type ExchangeResult struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Identity     string `json:"identity"`
}

// RefreshResult is the payload of POST /api/cli/auth/refresh.
type RefreshResult struct {
	IDToken   string `json:"id_token"`
	ExpiresIn int    `json:"expires_in"`
}

// ExchangeCode trades a single-use login code for a token set.
func (c *Client) ExchangeCode(code, state string) (*ExchangeResult, error) {
	body, err := c.doRequest("POST", "/api/cli/auth/exchange",
		map[string]string{"code": code, "state": state}, nil)
	if err != nil {
		return nil, err
	}
	var res ExchangeResult
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// RefreshToken mints a fresh ID token from a refresh token.
func (c *Client) RefreshToken(refreshToken string) (*RefreshResult, error) {
	body, err := c.doRequest("POST", "/api/cli/auth/refresh",
		map[string]string{"refresh_token": refreshToken}, nil)
	if err != nil {
		return nil, err
	}
	var res RefreshResult
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

// Revoke revokes the caller's refresh tokens server-side. The Client must
// carry a valid BearerToken.
func (c *Client) Revoke() error {
	_, err := c.doRequest("POST", "/api/cli/auth/revoke", nil, nil)
	return err
}
