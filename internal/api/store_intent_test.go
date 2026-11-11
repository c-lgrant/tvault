package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/c-lgrant/tvault/internal/clierr"
)

// storeBackends returns a Token Vault that records each store-ticket body and
// a webhook that counts the values it was sent.
func storeBackends(t *testing.T, ticketStatus int, ticketBody string) (*Client, *[]map[string]any, *int) {
	t.Helper()
	stored := 0
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stored++
		w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(webhook.Close)

	var asked []map[string]any
	tv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/vault/store-ticket" {
			w.Write([]byte(`{}`))
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(raw, &body)
		asked = append(asked, body)
		if ticketStatus != 0 {
			w.WriteHeader(ticketStatus)
			w.Write([]byte(ticketBody))
			return
		}
		w.Write([]byte(`{"ticket":"t","webhookUrl":"` + webhook.URL + `","expiresIn":60}`))
	}))
	t.Cleanup(tv.Close)
	return &Client{BaseURL: tv.URL, HTTP: tv.Client()}, &asked, &stored
}

// `tvault add` must say it means a new credential, so the server can refuse a
// name that exists; `tvault set` must not, because replacing is its job.
func TestCreateSendsTheCreateIntentAndSetDoesNot(t *testing.T) {
	client, asked, stored := storeBackends(t, 0, "")

	if err := client.CreateToken(CreateTokenRequest{ServiceName: "github", Type: "PlainText", Credential: "v"}); err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if err := client.StoreTokenViaWebhook("github", "PlainText", "v2"); err != nil {
		t.Fatalf("StoreTokenViaWebhook: %v", err)
	}
	if len(*asked) != 2 || *stored != 2 {
		t.Fatalf("tickets=%d stores=%d, want 2 and 2", len(*asked), *stored)
	}
	if got := (*asked)[0]["intent"]; got != "create" {
		t.Errorf("create sent intent %v, want create", got)
	}
	if _, has := (*asked)[1]["intent"]; has {
		t.Errorf("set sent an intent: %v", (*asked)[1])
	}
}

// A name that exists: the server refuses the ticket, so no value reaches the
// webhook and the stored one stays as it was.
func TestCreateOverAnExistingNameStoresNothing(t *testing.T) {
	client, _, stored := storeBackends(t, http.StatusConflict,
		`{"detail":{"code":"TOKEN_EXISTS","message":"A credential named 'github' already exists. To replace its value, rotate it (tvault set) instead of creating it again."}}`)

	err := client.CreateToken(CreateTokenRequest{ServiceName: "github", Type: "PlainText", Credential: "new-value"})
	if err == nil {
		t.Fatal("create over an existing name succeeded")
	}
	if *stored != 0 {
		t.Errorf("the webhook was sent %d value(s), want 0", *stored)
	}
	var ce *clierr.CLIError
	if !errors.As(err, &ce) {
		t.Fatalf("not a CLIError: %T", err)
	}
	if ce.Kind != clierr.KindUser || !strings.Contains(ce.Error(), "already exists") || strings.Contains(ce.Error(), "new-value") {
		t.Errorf("kind=%v error=%q", ce.Kind, ce.Error())
	}
}
