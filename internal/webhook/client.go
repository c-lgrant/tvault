package webhook

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RegisterInfo is the parsed result of the webhook's GET /v1/register-url.
type RegisterInfo struct {
	Code           string
	WebhookURL     string
	HMACSecretHash string
	ExpiresIn      int
}

// FetchRegisterURL calls GET {webhookURL}/v1/register-url and parses out the
// one-time code, the webhook's self-reported public URL, and the HMAC secret
// hash (carried in the registrationUrl query string).
func FetchRegisterURL(hc *http.Client, webhookURL string) (*RegisterInfo, error) {
	base := strings.TrimRight(webhookURL, "/")
	resp, err := hc.Get(base + "/v1/register-url")
	if err != nil {
		return nil, fmt.Errorf("reaching webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("webhook /v1/register-url returned %d", resp.StatusCode)
	}
	var raw struct {
		RegistrationURL string `json:"registrationUrl"`
		Code            string `json:"code"`
		ExpiresIn       int    `json:"expiresIn"`
		WebhookURL      string `json:"webhookUrl"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decoding /v1/register-url: %w", err)
	}
	// url.Parse rarely errors for strings; this mainly guards the nil-u deref below.
	u, err := url.Parse(raw.RegistrationURL)
	if err != nil {
		return nil, fmt.Errorf("parsing registrationUrl: %w", err)
	}
	hash := u.Query().Get("hmac_hash")
	if raw.Code == "" || raw.WebhookURL == "" || hash == "" {
		return nil, fmt.Errorf("webhook /v1/register-url response incomplete")
	}
	return &RegisterInfo{
		Code:           raw.Code,
		WebhookURL:     raw.WebhookURL,
		HMACSecretHash: hash,
		ExpiresIn:      raw.ExpiresIn,
	}, nil
}

// CheckHealth calls GET {webhookURL}/v1/health and returns nil only when the
// webhook reports healthy.
func CheckHealth(hc *http.Client, webhookURL string) error {
	base := strings.TrimRight(webhookURL, "/")
	resp, err := hc.Get(base + "/v1/health")
	if err != nil {
		return fmt.Errorf("reaching webhook: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("webhook /v1/health returned %d", resp.StatusCode)
	}
	var raw struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return fmt.Errorf("decoding /v1/health: %w", err)
	}
	if raw.Status != "healthy" {
		return fmt.Errorf("webhook reports status %q", raw.Status)
	}
	return nil
}

// WaitHealthy polls CheckHealth every 2s until it passes or timeout elapses.
func WaitHealthy(hc *http.Client, webhookURL string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for {
		if last = CheckHealth(hc, webhookURL); last == nil {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("webhook did not become healthy within %s: %w", timeout, last)
		}
		time.Sleep(2 * time.Second)
	}
}
