package cmd

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/config"
)

var userExit = clierr.ExitCode(&clierr.CLIError{Kind: clierr.KindUser})

// storeBackend serves the store-ticket route and a webhook /v1/store, and
// records the credential the webhook received.
type storeBackend struct {
	srv       *httptest.Server
	got       []string // accessToken values stored
	tokenPOST int      // POST /api/tokens (the value-less placeholder route)
}

func newStoreBackend(t *testing.T) *storeBackend {
	t.Helper()
	b := &storeBackend{}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api/tokens/"):
			w.Write([]byte(`{"serviceName":"svc","tokenType":"PlainText","type":"PlainText"}`))
		case r.Method == "POST" && r.URL.Path == "/api/vault/store-ticket":
			w.Write([]byte(`{"ticket":"tk","webhookUrl":"` + b.srv.URL + `/wh","expiresIn":60}`))
		case r.Method == "POST" && r.URL.Path == "/wh/v1/store":
			raw, _ := io.ReadAll(r.Body)
			var body struct {
				TokenData map[string]any `json:"tokenData"`
			}
			json.Unmarshal(raw, &body)
			v, _ := body.TokenData["accessToken"].(string)
			b.got = append(b.got, v)
			w.Write([]byte(`{}`))
		case r.Method == "POST" && r.URL.Path == "/api/tokens":
			b.tokenPOST++
			w.Write([]byte(`{}`))
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(b.srv.Close)
	setupContext(t, &config.Context{Type: "key", APIURL: b.srv.URL, Identity: "ci", APIKey: "tvkey_k"})
	return b
}

// withStdin simulates stdin: its contents and whether it is a terminal.
func withStdin(t *testing.T, content string, tty bool, hidden string) {
	t.Helper()
	rootCmd.SetIn(strings.NewReader(content))
	origTTY, origHidden, origMode := stdinIsTTY, readHidden, stdinMode
	stdinMode = func() os.FileMode { return 0 } // regular file: read to EOF
	stdinIsTTY = func() bool { return tty }
	readHidden = func(string) (string, error) { return hidden, nil }
	resetFlags(t)
	t.Cleanup(func() {
		rootCmd.SetIn(nil)
		stdinIsTTY, readHidden, stdinMode = origTTY, origHidden, origMode
		resetFlags(t)
	})
}

func TestAddValue_FromPipedStdin(t *testing.T) {
	b := newStoreBackend(t)
	withStdin(t, "s3cret\n\n", false, "")
	if _, _, err := runCLI(t, "add", "svc"); err != nil {
		t.Fatal(err)
	}
	// Only ONE trailing newline is trimmed.
	if len(b.got) != 1 || b.got[0] != "s3cret\n" {
		t.Errorf("stored %q, want [\"s3cret\\n\"]", b.got)
	}
}

func TestAddValue_ValueStdinFlagOnTTYStdin(t *testing.T) {
	b := newStoreBackend(t)
	withStdin(t, "piped\r\n", true, "should-not-be-used")
	if _, _, err := runCLI(t, "add", "svc", "--value-stdin"); err != nil {
		t.Fatal(err)
	}
	if len(b.got) != 1 || b.got[0] != "piped" {
		t.Errorf("stored %q", b.got)
	}
}

func TestAddValue_HiddenPromptOnTTY(t *testing.T) {
	b := newStoreBackend(t)
	withStdin(t, "ignored", true, "typed-secret")
	_, stderr, err := runCLI(t, "add", "svc")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.got) != 1 || b.got[0] != "typed-secret" {
		t.Errorf("stored %q", b.got)
	}
	if strings.Contains(stderr, "typed-secret") {
		t.Errorf("secret echoed on stderr: %q", stderr)
	}
}

func TestAddValue_FlagWarnsAboutHistory(t *testing.T) {
	b := newStoreBackend(t)
	withStdin(t, "", false, "")
	stdout, stderr, err := runCLI(t, "add", "svc", "--value", "flagval")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.got) != 1 || b.got[0] != "flagval" {
		t.Errorf("stored %q", b.got)
	}
	if !strings.Contains(stderr, "shell history") {
		t.Errorf("stderr should warn about shell history: %q", stderr)
	}
	if stdout != "" {
		t.Errorf("stdout = %q, want empty", stdout)
	}
}

func TestAddValue_EmptyStdinCreatesPlaceholder(t *testing.T) {
	b := newStoreBackend(t)
	withStdin(t, "", false, "")
	if _, _, err := runCLI(t, "add", "svc"); err != nil {
		t.Fatal(err)
	}
	if len(b.got) != 0 || b.tokenPOST != 1 {
		t.Errorf("want a value-less placeholder, got stored=%q placeholderPOSTs=%d", b.got, b.tokenPOST)
	}
}

func TestAddValue_EmptyExplicitStdinIsUserError(t *testing.T) {
	b := newStoreBackend(t)
	withStdin(t, "\n", false, "")
	_, _, err := runCLI(t, "add", "svc", "--value-stdin")
	if err == nil || clierr.ExitCode(err) != userExit {
		t.Errorf("err = %v, want a user error", err)
	}
	if len(b.got) != 0 || b.tokenPOST != 0 {
		t.Errorf("nothing should be stored")
	}
}

func TestSetValue_Modes(t *testing.T) {
	cases := []struct {
		name    string
		stdin   string
		tty     bool
		hidden  string
		args    []string
		want    string
		wantErr bool
	}{
		{"piped", "rot1\n", false, "", []string{"set", "svc"}, "rot1", false},
		{"flag", "", false, "", []string{"set", "svc", "--value", "rot2"}, "rot2", false},
		{"prompt", "", true, "rot3", []string{"tokens", "set", "svc"}, "rot3", false},
		{"value-stdin", "rot4\n", true, "", []string{"set", "svc", "--value-stdin"}, "rot4", false},
		{"empty pipe", "", false, "", []string{"set", "svc"}, "", true},
		{"empty prompt", "", true, "", []string{"set", "svc"}, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := newStoreBackend(t)
			withStdin(t, c.stdin, c.tty, c.hidden)
			_, _, err := runCLI(t, c.args...)
			if c.wantErr {
				if err == nil || clierr.ExitCode(err) != userExit {
					t.Errorf("want a user error, got %v", err)
				}
				if len(b.got) != 0 {
					t.Errorf("stored %q despite error", b.got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(b.got) != 1 || b.got[0] != c.want {
				t.Errorf("stored %q, want %q", b.got, c.want)
			}
		})
	}
}

// An open pipe that never sends anything (docker exec -i, harnesses) must not
// hang the command: without --value-stdin it counts as "no value".
func withSilentPipe(t *testing.T) {
	t.Helper()
	pr, pw := io.Pipe()
	t.Cleanup(func() { pw.Close() })
	withStdin(t, "", false, "")
	rootCmd.SetIn(pr)
	stdinMode = func() os.FileMode { return os.ModeNamedPipe }
	orig := stdinFirstByteWait
	stdinFirstByteWait = 50 * time.Millisecond
	t.Cleanup(func() { stdinFirstByteWait = orig })
}

func TestAdd_SilentOpenPipeCreatesPlaceholderWithoutHanging(t *testing.T) {
	b := newStoreBackend(t)
	withSilentPipe(t)
	if _, _, err := runCLI(t, "add", "svc"); err != nil {
		t.Fatal(err)
	}
	if len(b.got) != 0 || b.tokenPOST != 1 {
		t.Errorf("want a placeholder, got stored=%q placeholders=%d", b.got, b.tokenPOST)
	}
}

func TestSet_SilentOpenPipeErrorsWithHint(t *testing.T) {
	b := newStoreBackend(t)
	withSilentPipe(t)
	_, _, err := runCLI(t, "set", "svc")
	var ce *clierr.CLIError
	if err == nil || !errors.As(err, &ce) || ce.Kind != clierr.KindUser || !strings.Contains(ce.Hint, "--value-stdin") {
		t.Fatalf("err = %v, want a user error hinting --value-stdin", err)
	}
	if len(b.got) != 0 {
		t.Errorf("stored %q", b.got)
	}
}

func TestSet_PipeWithDataIsRead(t *testing.T) {
	b := newStoreBackend(t)
	withStdin(t, "piped\n", false, "")
	stdinMode = func() os.FileMode { return os.ModeNamedPipe }
	if _, _, err := runCLI(t, "set", "svc"); err != nil {
		t.Fatal(err)
	}
	if len(b.got) != 1 || b.got[0] != "piped" {
		t.Errorf("stored %q", b.got)
	}
}

func TestSet_ExplicitValueStdinWaitsOnSilentPipeNoTimeout(t *testing.T) {
	b := newStoreBackend(t)
	pr, pw := io.Pipe()
	withStdin(t, "", false, "")
	rootCmd.SetIn(pr)
	stdinMode = func() os.FileMode { return os.ModeNamedPipe }
	go func() { time.Sleep(150 * time.Millisecond); pw.Write([]byte("late\n")); pw.Close() }()
	if _, _, err := runCLI(t, "set", "svc", "--value-stdin"); err != nil {
		t.Fatal(err)
	}
	if len(b.got) != 1 || b.got[0] != "late" {
		t.Errorf("stored %q", b.got)
	}
}
