package api

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListAgents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agents" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Write([]byte(`[{"id":"a1","name":"pi-mixer","status":"active"},
		                 {"id":"a2","name":"nuc-bot","status":"suspended"}]`))
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	agents, err := client.ListAgents()
	if err != nil {
		t.Fatalf("ListAgents errored: %v", err)
	}
	if len(agents) != 2 || agents[0].Name != "pi-mixer" {
		t.Errorf("agents = %+v", agents)
	}
}

func TestCreateAgentReturnsKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(raw, &body)
		if body["name"] != "pi-mixer" {
			t.Errorf("body = %v", body)
		}
		// Backend create body has no "grants" field — grants are added
		// via separate POST /api/agents/{id}/grants calls.
		if _, ok := body["grants"]; ok {
			t.Errorf("create body must not carry grants: %v", body)
		}
		w.Write([]byte(`{"id":"a1","name":"pi-mixer","apiKey":"tvagent_newkey"}`))
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	res, err := client.CreateAgent("pi-mixer")
	if err != nil {
		t.Fatalf("CreateAgent errored: %v", err)
	}
	if res.APIKey != "tvagent_newkey" {
		t.Errorf("apiKey = %q", res.APIKey)
	}
	if res.ID != "a1" {
		t.Errorf("id = %q", res.ID)
	}
}

func TestDeleteAgentsBulkVsSingle(t *testing.T) {
	var paths []string
	var bulkBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.URL.Path == "/api/agents/bulk" {
			raw, _ := io.ReadAll(r.Body)
			json.Unmarshal(raw, &bulkBody)
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"success":true}`))
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	client.DeleteAgents([]string{"a1"})
	client.DeleteAgents([]string{"a1", "a2"})
	if paths[0] != "DELETE /api/agents/a1" {
		t.Errorf("single = %s", paths[0])
	}
	if paths[1] != "DELETE /api/agents/bulk" {
		t.Errorf("bulk = %s", paths[1])
	}
	// Backend BulkDeleteAgentsRequest pins the field name "agentIds".
	if _, ok := bulkBody["agentIds"]; !ok {
		t.Errorf("bulk body must use agentIds key: %v", bulkBody)
	}
}

func TestAddRemoveGrants(t *testing.T) {
	var reqs []string
	var addBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs = append(reqs, r.Method+" "+r.URL.Path)
		if r.Method == "POST" {
			raw, _ := io.ReadAll(r.Body)
			json.Unmarshal(raw, &addBody)
		}
		w.Write([]byte(`{"success":true}`))
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	if res := client.AddGrants("a1", []string{"github", "spotify"}); res.Err() != nil {
		t.Fatalf("AddGrants errored: %v", res.Err())
	}
	if res := client.RemoveGrants("a1", []string{"github"}); res.Err() != nil {
		t.Fatalf("RemoveGrants errored: %v", res.Err())
	}
	// Backend takes one service per POST. Its CreateGrantRequest model
	// REQUIRES both "agentId" and "serviceName" — omitting agentId is a 422.
	if reqs[0] != "POST /api/agents/a1/grants" || reqs[1] != "POST /api/agents/a1/grants" {
		t.Errorf("add reqs = %v", reqs[:2])
	}
	if addBody["serviceName"] == nil {
		t.Errorf("add body must use serviceName key: %v", addBody)
	}
	if addBody["agentId"] != "a1" {
		t.Errorf("add body must carry agentId=a1: %v", addBody)
	}
	// Backend revokes via path param: DELETE .../grants/{service}.
	if reqs[2] != "DELETE /api/agents/a1/grants/github" {
		t.Errorf("remove req = %s", reqs[2])
	}
}

func TestAddGrantsPartialFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		json.Unmarshal(raw, &body)
		if body["serviceName"] == "spotify" {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(`{"detail":"boom"}`))
			return
		}
		w.Write([]byte(`{"success":true}`))
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client()}
	res := client.AddGrants("a1", []string{"github", "spotify", "stripe"})
	if res.Err() == nil {
		t.Fatal("expected partial-failure error")
	}
	if len(res.OK) != 1 || res.OK[0] != "github" {
		t.Errorf("OK = %v, want [github]", res.OK)
	}
	if _, bad := res.Failed["spotify"]; !bad {
		t.Errorf("Failed should contain spotify: %v", res.Failed)
	}
	if len(res.Skipped) != 1 || res.Skipped[0] != "stripe" {
		t.Errorf("Skipped = %v, want [stripe]", res.Skipped)
	}
}

func TestAgentIdentityValidatesKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Agent-Key") != "tvagent_abc" {
			t.Errorf("missing X-Agent-Key header")
		}
		// The real /api/agents/credentials list response is {"grants":[...]}.
		// It carries no agent name, so AgentIdentity falls back to "agent".
		w.Write([]byte(`{"grants":[{"serviceName":"github"}]}`))
	}))
	defer srv.Close()
	client := &Client{BaseURL: srv.URL, HTTP: srv.Client(), AgentKey: "tvagent_abc"}
	name, err := client.AgentIdentity()
	if err != nil {
		t.Fatalf("AgentIdentity errored: %v", err)
	}
	if name != "agent" {
		t.Errorf("name = %q", name)
	}
}
