package auth

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/c-lgrant/tvault/internal/clierr"
)

// openBrowser is a package var so tests can stand in for the browser.
var openBrowser = func(rawURL string) error {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler"}
	default:
		cmd = "xdg-open"
	}
	args = append(args, rawURL)
	return exec.Command(cmd, args...).Start()
}

// manualInput is the source the manual flow reads the pasted code from. It's a
// package var so tests can stand in for stdin.
var manualInput io.Reader = os.Stdin

// getenv is a package var so tests can stand in for environment lookups.
var getenv = os.Getenv

// callbackResult is what the browser POSTs to the loopback server (loopback
// flow) or what the user pastes in (manual flow).
type callbackResult struct {
	code  string
	state string
}

func randString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// shouldUseManualFlow decides whether to use the manual code-paste flow instead
// of the loopback browser redirect. It returns true when forceManual is set, or
// when the session looks headless (SSH, or a Linux session with no display).
func shouldUseManualFlow(forceManual bool) bool {
	if forceManual {
		return true
	}
	if getenv("SSH_CONNECTION") != "" {
		return true
	}
	if runtime.GOOS == "linux" && getenv("DISPLAY") == "" && getenv("WAYLAND_DISPLAY") == "" {
		return true
	}
	return false
}

// runManualFlow runs the manual code-paste login flow: print a mode=manual URL
// (no loopback port), then read the single-use code the user pastes from stdin.
func runManualFlow(frontendURL, state string) (*callbackResult, error) {
	authURL := fmt.Sprintf("%s/cli/auth?client=tvault-cli&mode=manual&state=%s", frontendURL, state)

	fmt.Fprintf(os.Stderr,
		"Open this URL in a browser on any machine to sign in:\n\n  %s\n\nThen paste the code shown in your browser here:\n> ",
		authURL)

	line, err := bufio.NewReader(manualInput).ReadString('\n')
	if err != nil && err != io.EOF {
		return nil, &clierr.CLIError{Kind: clierr.KindAuth, Message: "could not read the pasted code: " + err.Error()}
	}
	code := strings.TrimSpace(line)
	if code == "" {
		return nil, &clierr.CLIError{Kind: clierr.KindAuth, Message: "no code entered — run `tvault login` again"}
	}
	return &callbackResult{code: code, state: state}, nil
}

// runLoginFlow runs the appropriate login dance. When the session looks
// headless (or forceManual is set), it uses the manual code-paste flow. Other-
// wise it binds an ephemeral localhost server, opens the browser to the
// frontend's /cli/auth page, and waits for the browser to POST {code,state}
// back. If launching the browser fails, it falls back to the manual flow.
// timeout bounds the loopback wait.
func runLoginFlow(frontendURL string, forceManual bool, timeout time.Duration) (*callbackResult, error) {
	state, err := randString(24)
	if err != nil {
		return nil, err
	}

	if shouldUseManualFlow(forceManual) {
		return runManualFlow(frontendURL, state)
	}

	// Bind an ephemeral port on loopback.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, &clierr.CLIError{Kind: clierr.KindNetwork, Message: "could not bind a local callback port: " + err.Error()}
	}
	closeListener := func() { _ = ln.Close() }
	port := ln.Addr().(*net.TCPAddr).Port

	resultCh := make(chan callbackResult, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		// CORS — the browser is on the frontend origin (tokenvault.uk by
		// default), so its fetch to this loopback listener is cross-origin.
		// Set headers on every response so both the OPTIONS preflight and
		// the actual POST are accepted. Allow-Origin: * is safe here because
		// the host check below + per-flow random state are what authorize
		// the request — CORS only authorizes the browser.
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Max-Age", "300")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Defense-in-depth against DNS-rebinding: only accept requests
		// addressed to the loopback host this flow is bound to.
		if r.Host != fmt.Sprintf("127.0.0.1:%d", port) && r.Host != fmt.Sprintf("localhost:%d", port) {
			http.Error(w, "bad host", http.StatusBadRequest)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		var payload struct {
			Code  string `json:"code"`
			State string `json:"state"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, "bad payload", http.StatusBadRequest)
			return
		}
		if payload.State != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
		select {
		case resultCh <- callbackResult{code: payload.Code, state: payload.State}:
		default:
		}
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go srv.Serve(ln)
	shutdownServer := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}

	authURL := fmt.Sprintf("%s/cli/auth?client=tvault-cli&port=%d&state=%s",
		frontendURL, port, state)

	if err := openBrowser(authURL); err != nil {
		// The loopback would be unreachable anyway if no browser can open
		// here — fall back to the manual code-paste flow.
		shutdownServer()
		closeListener()
		fmt.Fprintf(os.Stderr, "(couldn't open a browser — switching to manual entry)\n\n")
		return runManualFlow(frontendURL, state)
	}
	fmt.Fprintf(os.Stderr, "Opening your browser to sign in…\nIf it does not open, visit:\n\n  %s\n\n", authURL)

	// Committed to the loopback wait; ensure the server is stopped on exit.
	defer shutdownServer()

	select {
	case res := <-resultCh:
		return &res, nil
	case <-time.After(timeout):
		return nil, &clierr.CLIError{
			Kind:    clierr.KindAuth,
			Message: "timed out waiting for browser login — run `tvault login` again",
		}
	}
}
