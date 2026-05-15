package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"runtime"
	"testing"
)

// errFakeBrowser stands in for a browser-launch failure in tests.
var errFakeBrowser = errors.New("fake browser launch failure")

// runtimeIsLinux reports whether the test is running on Linux, where a session
// with no DISPLAY/WAYLAND_DISPLAY looks headless.
func runtimeIsLinux() bool { return runtime.GOOS == "linux" }

// errorsAs is a thin wrapper so test files do not import errors directly.
func errorsAs(err error, target any) bool { return errors.As(err, target) }

func mustParseQuery(t *testing.T, rawURL string) map[string]string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse browser url: %v", err)
	}
	q := u.Query()
	return map[string]string{
		"state": q.Get("state"),
		"port":  q.Get("port"),
	}
}

func postCallback(t *testing.T, port, code, state string) {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"code": code, "state": state})
	http.Post("http://localhost:"+port+"/callback", "application/json", bytes.NewReader(payload))
}

func contains(haystack []byte, needle string) bool {
	return bytes.Contains(haystack, []byte(needle))
}
