// Package auth bridges stored contexts and ready-to-use API clients, and
// drives the browser login flow.
package auth

import (
	"errors"
	"time"

	"github.com/c-lgrant/tvault/internal/api"
	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/config"
)

// refreshSkew is how long before actual expiry we proactively refresh.
const refreshSkew = 5 * time.Minute

// ClientFor returns an api.Client ready to make authenticated requests for
// the given context. For admin contexts it refreshes the in-memory ID token
// when absent or within refreshSkew of expiry; for agent contexts it attaches
// the stored key. debug toggles HTTP request logging.
func ClientFor(ctx *config.Context, debug bool) (*api.Client, error) {
	client := api.New(ctx.APIURL, 0)
	client.Debug = debug

	switch ctx.Type {
	case "agent":
		client.AgentKey = ctx.AgentKey
		return client, nil

	case "admin":
		token, expiresAt := ctx.IDToken()
		stale := token == "" || time.Until(time.Unix(expiresAt, 0)) < refreshSkew
		if stale {
			res, err := client.RefreshToken(ctx.RefreshToken)
			if err != nil {
				// A rejected refresh token means the session is dead.
				var ce *clierr.CLIError
				if errors.As(err, &ce) && ce.Kind == clierr.KindAuth {
					return nil, &clierr.CLIError{
						Kind:    clierr.KindAuth,
						Message: "session expired — run `tvault login` to reauth",
					}
				}
				return nil, err
			}
			token = res.IDToken
			expiresAt = time.Now().Add(time.Duration(res.ExpiresIn) * time.Second).Unix()
			ctx.SetIDToken(token, expiresAt)
		}
		client.BearerToken = token
		return client, nil

	default:
		return nil, &clierr.CLIError{
			Kind:    clierr.KindUser,
			Message: "context has unknown type " + ctx.Type,
		}
	}
}
