package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVaultLockUnlock(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.Write([]byte(`{"isLocked":true}`))
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	if err := client.VaultLock(); err != nil {
		t.Fatalf("VaultLock errored: %v", err)
	}
	if err := client.VaultUnlock(); err != nil {
		t.Fatalf("VaultUnlock errored: %v", err)
	}
	if paths[0] != "POST /api/vault/lock" || paths[1] != "POST /api/vault/lock/clear" {
		t.Errorf("paths = %v", paths)
	}
}

func TestVaultStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"isLocked":true,"vaultMode":"platform"}`))
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	st, err := client.VaultStatus()
	if err != nil {
		t.Fatalf("VaultStatus errored: %v", err)
	}
	if !st.IsLocked || st.VaultMode != "platform" {
		t.Errorf("status = %+v", st)
	}
}
