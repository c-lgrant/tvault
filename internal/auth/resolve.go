// Package auth bridges stored contexts and ready-to-use API clients, and
// drives the browser login flow.
package auth

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/c-lgrant/tvault/internal/api"
	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/config"
)

// refreshSkew is how long before actual expiry we proactively refresh.
const refreshSkew = 5 * time.Minute

// ClientFor returns an api.Client ready to make authenticated requests for
// the given context. For admin contexts it reuses a cached ID token, and
// refreshes only when none is cached or it is within refreshSkew of expiry
// (see adminIDToken); for agent and key contexts it
// attaches the stored key as the bearer credential. debug toggles HTTP request logging.
func ClientFor(ctx *config.Context, debug bool) (*api.Client, error) {
	client := api.New(ctx.APIURL, 0)
	client.Debug = debug

	switch ctx.Type {
	case "agent":
		client.AgentKey = ctx.AgentKey
		return client, nil

	case "key":
		// Scoped keys authenticate with the bearer key itself — no Firebase
		// session, nothing to refresh.
		client.APIKey = ctx.APIKey
		return client, nil

	case "admin":
		token, err := adminIDToken(client, ctx, debug)
		if err != nil {
			return nil, err
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

func fresh(token string, expiresAt int64) bool {
	return token != "" && time.Until(time.Unix(expiresAt, 0)) >= refreshSkew
}

// adminIDToken returns a usable ID token for an admin context. It tries, in
// order: this process's token, the on-disk cache shared by every tvault
// process, then a refresh. The refresh runs under a cross-process lock and
// re-reads the cache first, so a burst of parallel calls makes one refresh.
// Cache and lock failures only cost the sharing; they never fail the command.
func adminIDToken(client *api.Client, ctx *config.Context, debug bool) (string, error) {
	logf := func(format string, args ...any) {
		if debug {
			fmt.Fprintf(os.Stderr, "[debug] id token: "+format+"\n", args...)
		}
	}

	if token, exp := ctx.IDToken(); fresh(token, exp) {
		return token, nil
	}
	if token, exp := config.CachedIDToken(ctx); fresh(token, exp) {
		logf("cache hit")
		ctx.SetIDToken(token, exp)
		return token, nil
	}

	unlock, err := config.LockIDTokenCache()
	if err != nil {
		logf("refreshing without the cache lock: %v", err)
	} else {
		defer unlock()
		// Another process may have refreshed while this one waited.
		if token, exp := config.CachedIDToken(ctx); fresh(token, exp) {
			logf("cache hit after wait")
			ctx.SetIDToken(token, exp)
			return token, nil
		}
	}

	res, err := client.RefreshToken(ctx.RefreshToken)
	if err != nil {
		// A rejected refresh token means the session is dead.
		var ce *clierr.CLIError
		if errors.As(err, &ce) && ce.Kind == clierr.KindAuth {
			return "", &clierr.CLIError{
				Kind:    clierr.KindAuth,
				Message: "session expired — run `tvault login` to reauth",
			}
		}
		return "", err
	}
	exp := time.Now().Add(time.Duration(res.ExpiresIn) * time.Second).Unix()
	ctx.SetIDToken(res.IDToken, exp)
	if err := config.StoreIDToken(ctx, res.IDToken, exp); err != nil {
		logf("could not cache the token: %v", err)
	}
	return res.IDToken, nil
}
