package webhook

import "testing"

func TestMethodsRegistry(t *testing.T) {
	ms := Methods()
	if len(ms) != 4 {
		t.Fatalf("expected 4 methods, got %d", len(ms))
	}
	wantIDs := map[string]bool{"ngrok": true, "cloudflare": true, "tailscale": true, "custom": true}
	for _, m := range ms {
		if !wantIDs[m.ID] {
			t.Errorf("unexpected method id %q", m.ID)
		}
		if m.Label == "" || m.Description == "" || m.HelpURL == "" {
			t.Errorf("method %q has empty metadata: %+v", m.ID, m)
		}
		if len(m.Params) == 0 {
			t.Errorf("method %q has no params", m.ID)
		}
		for _, p := range m.Params {
			if p.Key == "" || p.Prompt == "" {
				t.Errorf("method %q has a malformed param: %+v", m.ID, p)
			}
		}
	}
}

func TestMethodByID(t *testing.T) {
	for _, id := range []string{"ngrok", "cloudflare", "tailscale", "custom"} {
		m, ok := MethodByID(id)
		if !ok || m.ID != id {
			t.Errorf("MethodByID(%q) = %+v, %v", id, m, ok)
		}
	}
	if _, ok := MethodByID("nope"); ok {
		t.Error("MethodByID(nope) should return ok=false")
	}
}
