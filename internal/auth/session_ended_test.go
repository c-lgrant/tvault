package auth

import (
	"strings"
	"testing"

	"github.com/c-lgrant/tvault/internal/clierr"
)

func TestSessionEndedMessageNamesTheAgeLimit(t *testing.T) {
	aged := &clierr.CLIError{
		Kind:     clierr.KindAuth,
		Response: "401 — CLI session ended: an admin sign-in lasts 8 hours — run `tvault login` again",
	}
	got := sessionEndedMessage(aged)
	if !strings.Contains(got, "lasts 8 hours") || !strings.Contains(got, "tvault login") {
		t.Errorf("message = %q, want the 8 hour reason and the login command", got)
	}

	inMessage := &clierr.CLIError{Kind: clierr.KindAuth, Message: "an admin sign-in lasts 24 hours"}
	if got := sessionEndedMessage(inMessage); !strings.Contains(got, "lasts 24 hours") {
		t.Errorf("message = %q, want the reason from Message too", got)
	}

	for _, other := range []*clierr.CLIError{
		nil,
		{Kind: clierr.KindAuth, Response: "401 — CLI session ended — run `tvault login` again"},
		{Kind: clierr.KindAuth, Response: "401 — lasts many hours"},
	} {
		got := sessionEndedMessage(other)
		if strings.Contains(got, "lasts") || !strings.Contains(got, "run `tvault login`") {
			t.Errorf("message = %q, want the plain form", got)
		}
	}
}
