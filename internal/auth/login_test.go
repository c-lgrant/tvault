package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/c-lgrant/tvault/internal/clierr"
)

// forceLoopbackEnv makes shouldUseManualFlow(false) return false by standing in
// for environment lookups: no SSH_CONNECTION, and a DISPLAY set so a Linux
// session does not look headless.
func forceLoopbackEnv(t *testing.T) {
	t.Helper()
	orig := getenv
	t.Cleanup(func() { getenv = orig })
	getenv = func(k string) string {
		if k == "DISPLAY" {
			return ":0"
		}
		return ""
	}
}

func TestLoginFlowReceivesCodeFromCallback(t *testing.T) {
	forceLoopbackEnv(t)
	// Stand in for the browser: when the CLI "opens" the browser, parse the
	// state out of the URL and POST {code,state} to the loopback callback.
	origOpen := openBrowser
	defer func() { openBrowser = origOpen }()
	openBrowser = func(rawURL string) error {
		go func() {
			u := mustParseQuery(t, rawURL)
			payload, _ := json.Marshal(map[string]string{
				"code":  "test-code",
				"state": u["state"],
			})
			http.Post("http://localhost:"+u["port"]+"/callback",
				"application/json", bytes.NewReader(payload))
		}()
		return nil
	}

	got, err := runLoginFlow("https://tokenvault.uk", false, 3*time.Second)
	if err != nil {
		t.Fatalf("runLoginFlow errored: %v", err)
	}
	if got.code != "test-code" {
		t.Errorf("code = %q, want test-code", got.code)
	}
	if got.state == "" {
		t.Error("state was not generated")
	}
}

func TestLoginFlowTimesOut(t *testing.T) {
	forceLoopbackEnv(t)
	origOpen := openBrowser
	defer func() { openBrowser = origOpen }()
	openBrowser = func(string) error { return nil } // browser never responds

	_, err := runLoginFlow("https://tokenvault.uk", false, 200*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestLoginFlowRejectsBadState(t *testing.T) {
	forceLoopbackEnv(t)
	// Stand in for the browser, but POST a state that does NOT match the
	// one the flow generated. The callback must be rejected and runLoginFlow
	// must time out rather than return the bogus result.
	origOpen := openBrowser
	defer func() { openBrowser = origOpen }()
	openBrowser = func(rawURL string) error {
		go func() {
			u := mustParseQuery(t, rawURL)
			payload, _ := json.Marshal(map[string]string{
				"code":  "x",
				"state": "wrong-state",
			})
			http.Post("http://localhost:"+u["port"]+"/callback",
				"application/json", bytes.NewReader(payload))
		}()
		return nil
	}

	_, err := runLoginFlow("https://tokenvault.uk", false, 300*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error — bad-state callback must be ignored")
	}
}

func TestShouldUseManualFlow(t *testing.T) {
	cases := []struct {
		name        string
		forceManual bool
		env         map[string]string
		want        bool
	}{
		{"force flag", true, map[string]string{}, true},
		{"ssh connection set", false, map[string]string{"SSH_CONNECTION": "1.2.3.4 5 6.7.8.9 10"}, true},
		{"linux no display", false, map[string]string{}, runtimeIsLinux()},
		{"none set", false, map[string]string{"DISPLAY": ":0"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orig := getenv
			t.Cleanup(func() { getenv = orig })
			getenv = func(k string) string { return tc.env[k] }
			if got := shouldUseManualFlow(tc.forceManual); got != tc.want {
				t.Errorf("shouldUseManualFlow(%v) = %v, want %v", tc.forceManual, got, tc.want)
			}
		})
	}
}

func TestRunManualFlowReadsCode(t *testing.T) {
	orig := manualInput
	defer func() { manualInput = orig }()
	manualInput = strings.NewReader("somecode\n")

	got, err := runManualFlow("https://tokenvault.uk", "the-state")
	if err != nil {
		t.Fatalf("runManualFlow errored: %v", err)
	}
	if got.code != "somecode" {
		t.Errorf("code = %q, want somecode", got.code)
	}
	if got.state != "the-state" {
		t.Errorf("state = %q, want the-state", got.state)
	}
}

func TestRunManualFlowEmptyInput(t *testing.T) {
	orig := manualInput
	defer func() { manualInput = orig }()
	manualInput = strings.NewReader("   \n")

	_, err := runManualFlow("https://tokenvault.uk", "the-state")
	if err == nil {
		t.Fatal("expected error on empty input")
	}
	var ce *clierr.CLIError
	if !errorsAs(err, &ce) || ce.Kind != clierr.KindAuth {
		t.Errorf("want KindAuth CLIError, got %#v", err)
	}
}

func TestRunLoginFlowManualWhenForced(t *testing.T) {
	orig := manualInput
	defer func() { manualInput = orig }()
	manualInput = strings.NewReader("pasted-code\n")

	// openBrowser must not be called in the manual flow.
	origOpen := openBrowser
	defer func() { openBrowser = origOpen }()
	openBrowser = func(string) error {
		t.Error("openBrowser called in manual flow")
		return nil
	}

	got, err := runLoginFlow("https://tokenvault.uk", true, time.Second)
	if err != nil {
		t.Fatalf("runLoginFlow errored: %v", err)
	}
	if got.code != "pasted-code" {
		t.Errorf("code = %q, want pasted-code", got.code)
	}
}

func TestRunLoginFlowFallsBackOnBrowserError(t *testing.T) {
	forceLoopbackEnv(t)
	orig := manualInput
	defer func() { manualInput = orig }()
	manualInput = strings.NewReader("fallback-code\n")

	origOpen := openBrowser
	defer func() { openBrowser = origOpen }()
	openBrowser = func(string) error { return errFakeBrowser }

	got, err := runLoginFlow("https://tokenvault.uk", false, time.Second)
	if err != nil {
		t.Fatalf("runLoginFlow errored: %v", err)
	}
	if got.code != "fallback-code" {
		t.Errorf("code = %q, want fallback-code", got.code)
	}
}
