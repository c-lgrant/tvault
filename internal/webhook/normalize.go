package webhook

import "strings"

// stripScheme returns s without an http:// or https:// prefix and without a
// trailing slash. Useful for params that want a bare hostname (e.g. ngrok's
// --url= flag) — the user can paste a full URL and we still get it right.
func stripScheme(s string) string {
	s = strings.TrimSpace(s)
	for _, p := range []string{"https://", "http://"} {
		if strings.HasPrefix(strings.ToLower(s), p) {
			s = s[len(p):]
			break
		}
	}
	return strings.TrimRight(s, "/")
}

// ensureHTTPS returns s with an https:// prefix and no trailing slash. Empty
// input is returned unchanged so the wizard's required-value check still
// fires. http:// is upgraded to https:// — public webhook URLs are always
// over TLS.
func ensureHTTPS(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	s = strings.TrimRight(s, "/")
	low := strings.ToLower(s)
	switch {
	case strings.HasPrefix(low, "https://"):
		return s
	case strings.HasPrefix(low, "http://"):
		return "https://" + s[len("http://"):]
	default:
		return "https://" + s
	}
}
