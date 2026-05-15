package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExchangeCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cli/auth/exchange" {
			t.Errorf("path = %s", r.URL.Path)
		}
		raw, _ := io.ReadAll(r.Body)
		var got map[string]string
		json.Unmarshal(raw, &got)
		if got["code"] != "the-code" || got["state"] != "the-state" {
			t.Errorf("body = %v", got)
		}
		w.Write([]byte(`{"id_token":"idt","refresh_token":"rt","expires_in":3600,"identity":"conor@x.y"}`))
	}))
	defer srv.Close()

	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	res, err := client.ExchangeCode("the-code", "the-state")
	if err != nil {
		t.Fatalf("ExchangeCode errored: %v", err)
	}
	if res.IDToken != "idt" || res.RefreshToken != "rt" || res.ExpiresIn != 3600 || res.Identity != "conor@x.y" {
		t.Errorf("result = %+v", res)
	}
}

func TestRefreshToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/cli/auth/refresh" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Write([]byte(`{"id_token":"new-idt","expires_in":3600}`))
	}))
	defer srv.Close()

	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	res, err := client.RefreshToken("rt")
	if err != nil {
		t.Fatalf("RefreshToken errored: %v", err)
	}
	if res.IDToken != "new-idt" || res.ExpiresIn != 3600 {
		t.Errorf("result = %+v", res)
	}
}
