package cmd

import (
	"fmt"
	"os"

	"github.com/c-lgrant/tvault/internal/api"
	"github.com/c-lgrant/tvault/internal/auth"
	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/config"
	"github.com/c-lgrant/tvault/internal/output"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type cmdContext struct {
	Client      *api.Client
	Ctx         *config.Context
	ContextName string
	Format      output.Format
	IsTTY       bool
}

func (cc *cmdContext) label() string {
	return fmt.Sprintf("%s (%s · %s)", cc.ContextName, cc.Ctx.Type, cc.Ctx.Identity)
}

// resolve loads the active context, builds an authenticated API client, and
// resolves the output format. adminOnly rejects agent contexts up front.
// contextOverride reads --context, falling back to its --ctx alias.
// Both set → --context wins.
func contextOverride(cmd *cobra.Command) string {
	v, _ := cmd.Flags().GetString("context")
	if v != "" {
		return v
	}
	v, _ = cmd.Flags().GetString("ctx")
	return v
}

func resolve(cmd *cobra.Command, adminOnly bool) (*cmdContext, error) {
	override := contextOverride(cmd)
	debug, _ := cmd.Flags().GetBool("debug")
	formatFlag, _ := cmd.Flags().GetString("format")

	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	ctx, name, err := cfg.ActiveContext(override)
	if err != nil {
		return nil, err
	}
	if adminOnly && ctx.Type != "admin" {
		return nil, &clierr.CLIError{
			Kind:    clierr.KindUser,
			Command: cmd.CommandPath(),
			Message: fmt.Sprintf("requires an admin context — %q is an agent context; switch with `tvault ctx use <admin-ctx>`", name),
		}
	}
	client, err := auth.ClientFor(ctx, debug)
	if err != nil {
		return nil, err
	}
	if dryRun, _ := cmd.Flags().GetBool("dry-run"); dryRun {
		client.DryRun = true
	}
	isTTY := term.IsTerminal(int(os.Stdout.Fd()))
	return &cmdContext{
		Client:      client,
		Ctx:         ctx,
		ContextName: name,
		Format:      output.ResolveFormat(formatFlag, isTTY),
		IsTTY:       isTTY,
	}, nil
}

// enrich annotates a *clierr.CLIError with command/context/hint details that
// only the command layer knows. Non-CLIError values pass through untouched.
func enrich(cmd *cobra.Command, cc *cmdContext, err error) error {
	if err == nil {
		return nil
	}
	var ce *clierr.CLIError
	if asCLIErr(err, &ce) {
		if ce.Command == "" {
			ce.Command = cmd.CommandPath()
		}
		if ce.Context == "" && cc != nil {
			ce.Context = cc.label()
		}
		if ce.Kind == clierr.KindVaultLocked && ce.Hint == "" && cc != nil && cc.Ctx.Type == "admin" {
			ce.Hint = "tvault vault unlock"
		}
	}
	return err
}
