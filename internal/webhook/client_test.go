package webhook

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchRegisterURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/register-url" {
			w.WriteHeader(404)
			return
		}
		w.Write([]byte(`{
			"registrationUrl": "https://tokenvault.uk/vault/webhook-bind?code=c1&webhook_url=x&hmac_hash=HASH9",
			"code": "c1",
			"expiresIn": 300,
			"webhookUrl": "https://wh.example.com"
		}`))
	}))
	defer srv.Close()
	info, err := FetchRegisterURL(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("FetchRegisterURL: %v", err)
	}
	if info.Code != "c1" || info.WebhookURL != "https://wh.example.com" || info.HMACSecretHash != "HASH9" {
		t.Errorf("info = %+v", info)
	}
}

func TestFetchRegisterURLIncomplete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"registrationUrl":"https://x/?code=c1","code":"","webhookUrl":""}`))
	}))
	defer srv.Close()
	if _, err := FetchRegisterURL(srv.Client(), srv.URL); err == nil {
		t.Error("incomplete register-url response should error")
	}
}

func TestCheckHealthHealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"healthy"}`))
	}))
	defer srv.Close()
	if err := CheckHealth(srv.Client(), srv.URL); err != nil {
		t.Errorf("CheckHealth healthy: %v", err)
	}
}

func TestCheckHealthUnhealthy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"degraded"}`))
	}))
	defer srv.Close()
	if err := CheckHealth(srv.Client(), srv.URL); err == nil {
		t.Error("degraded status should error")
	}
}

func TestFetchRegisterURLNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if _, err := FetchRegisterURL(srv.Client(), srv.URL); err == nil {
		t.Error("non-200 should error")
	}
}

func TestCheckHealthNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	if err := CheckHealth(srv.Client(), srv.URL); err == nil {
		t.Error("non-200 should error")
	}
}

func TestFetchRegisterURLBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	}))
	defer srv.Close()
	if _, err := FetchRegisterURL(srv.Client(), srv.URL); err == nil {
		t.Error("bad JSON should error")
	}
}

func TestCheckHealthBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`not json`))
	}))
	defer srv.Close()
	if err := CheckHealth(srv.Client(), srv.URL); err == nil {
		t.Error("bad JSON should error")
	}
}
