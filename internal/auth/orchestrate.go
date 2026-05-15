package auth

import (
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

// LoginAgent validates a tvagent_* key and persists it as an agent context.
func LoginAgent(contextName, apiURL, agentKey string) error {
	if contextName == "" {
		return &clierr.CLIError{Kind: clierr.KindUser, Message: "agent login needs a context name (--as <name>)"}
	}
	client := api.New(apiURL, 0)
	client.AgentKey = agentKey
	identity, err := client.AgentIdentity() // defined in PR #4 Task 4.1; see note below
	if err != nil {
		return err
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	cfg.Contexts[contextName] = &config.Context{
		Type:     "agent",
		APIURL:   apiURL,
		Identity: identity,
		AgentKey: agentKey,
	}
	cfg.Current = contextName
	return cfg.Save()
}
