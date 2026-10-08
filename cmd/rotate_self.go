package cmd

import (
	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/config"
)

// selfPrincipal returns the id and name of the key or agent the active
// context is logged in as. Rotating your own key needs no scope, but looking
// yourself up by name would (keys:manage / agents:read), so --self goes
// through whoami.
func selfPrincipal(cc *cmdContext, wantType, command string) (id, name string, err error) {
	if cc.Ctx.Type != wantType {
		return "", "", &clierr.CLIError{Kind: clierr.KindUser, Command: command,
			Message: "--self needs a " + wantType + " context, but " + cc.label() + " is not one"}
	}
	who, err := cc.Client.Whoami()
	if err != nil {
		return "", "", err
	}
	if who.Principal.ID == "" {
		return "", "", &clierr.CLIError{Kind: clierr.KindUser, Command: command,
			Message: "the server did not report this context's own id (it may predate scoped keys)"}
	}
	name = who.Principal.Name
	if name == "" {
		name = who.Principal.ID
	}
	return who.Principal.ID, name, nil
}

// storeRotatedKey swaps the active context over to the new key, so the
// context keeps working after the old one is invalidated.
func storeRotatedKey(cc *cmdContext, newKey string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, ok := cfg.Contexts[cc.ContextName]
	if !ok {
		return &clierr.CLIError{Kind: clierr.KindUser,
			Message: "rotated, but context " + cc.ContextName + " is gone; log in again with the key printed above"}
	}
	if ctx.Type == "agent" {
		ctx.AgentKey = newKey
	} else {
		ctx.APIKey = newKey
	}
	if err := cfg.Save(); err != nil {
		return &clierr.CLIError{Kind: clierr.KindUser,
			Message: "the rotation succeeded and the new key is printed on stdout, but saving it to context " +
				cc.ContextName + " failed: " + err.Error(),
			Hint: "the old key no longer works — store the new key now: `printf %s \"$KEY\" | tvault login --key-stdin --as " + cc.ContextName + "`"}
	}
	return nil
}
