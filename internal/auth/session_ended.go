package auth

import (
	"regexp"

	"github.com/c-lgrant/tvault/internal/clierr"
)

// The control plane says how long an admin sign-in lasts when it ends one for
// its age: "CLI session ended: an admin sign-in lasts 8 hours — run ...".
var signInLasts = regexp.MustCompile(`lasts (\d{1,4}) hours`)

// sessionEndedMessage is what the CLI says when the control plane refuses to
// renew an admin sign-in. It names the reason when the server gave one, so the
// person knows this is the normal end of a sign-in and not a fault.
func sessionEndedMessage(refused *clierr.CLIError) string {
	if refused != nil {
		if m := signInLasts.FindStringSubmatch(refused.Response + " " + refused.Message); m != nil {
			return "your admin sign-in has ended: a sign-in lasts " + m[1] +
				" hours and nothing renews it — run `tvault login` to sign in again"
		}
	}
	return "your admin sign-in has ended — run `tvault login` to sign in again"
}
