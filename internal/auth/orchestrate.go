package auth

import (
	"strings"
	"time"

	"github.com/c-lgrant/tvault/internal/api"
	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/config"
)

// LoginOptions configures an admin login.
type LoginOptions struct {
	ContextName string        // name to store the context under; "" → "default"
	APIURL      string        // API base URL
	FrontendURL string        // frontend base URL (hosts /cli/auth)
	ForceManual bool          // force the manual code-paste flow (SSH/headless)
	Timeout     time.Duration // overall wait budget; 0 → 3 minutes
}

// Login runs the full admin login: browser dance → code exchange → persist a
// new admin context and make it current.
func Login(opts LoginOptions) error {
	name := opts.ContextName
	if name == "" {
		name = "default"
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 3 * time.Minute
	}

	cb, err := runLoginFlow(opts.FrontendURL, opts.ForceManual, timeout)
	if err != nil {
		return err
	}

	client := api.New(opts.APIURL, 0)
	res, err := client.ExchangeCode(cb.code, cb.state)
	if err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	cfg.Contexts[name] = &config.Context{
		Type:         "admin",
		APIURL:       opts.APIURL,
		Identity:     res.Identity,
		RefreshToken: res.RefreshToken,
	}
	cfg.Current = name
	return cfg.Save()
}

// KeyContextType returns the context type implied by an API key's prefix:
// "agent" for tvagent_*, "key" for tvkey_*, "" for anything else.
func KeyContextType(key string) string {
	switch {
	case strings.HasPrefix(key, "tvagent_"):
		return "agent"
	case strings.HasPrefix(key, "tvkey_"):
		return "key"
	default:
		return ""
	}
}

// LoginKey validates an API key and persists it as a context, detecting the
// type from the prefix: tvagent_* → agent context, tvkey_* → key context.
func LoginKey(contextName, apiURL, key string) error {
	if contextName == "" {
		return &clierr.CLIError{Kind: clierr.KindUser, Message: "key login needs a context name (--as <name>)"}
	}
	typ := KeyContextType(key)
	if typ == "" {
		return &clierr.CLIError{Kind: clierr.KindUser, Message: "unrecognized key — expected a tvagent_* or tvkey_* key"}
	}
	client := api.New(apiURL, 0)
	ctx := &config.Context{Type: typ, APIURL: apiURL}
	if typ == "agent" {
		client.AgentKey = key
		ctx.AgentKey = key
		identity, err := client.AgentIdentity()
		if err != nil {
			return err
		}
		ctx.Identity = identity
	} else {
		client.APIKey = key
		ctx.APIKey = key
		who, err := client.Whoami()
		if err != nil {
			return err
		}
		ctx.Identity = who.Principal.Name
		if ctx.Identity == "" {
			ctx.Identity = "key"
		}
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	cfg.Contexts[contextName] = ctx
	cfg.Current = contextName
	return cfg.Save()
}
