package cmd

import (
	"fmt"
	"os"
	"strings"

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
// resolves the output format. Every context type (admin, agent, key) is
// accepted: the server is the sole enforcer of what a principal may do, and
// its SCOPE_DENIED / HUMAN_ONLY answers map to distinct exit codes.
// contextOverride reads --context, falling back to its --ctx alias.
// Both set → --context wins.
//
// TVAULT_CONTEXT pins the context for the whole process: it is used with no
// flag, and pinGuard refuses anything that would use or change another one.
func contextOverride(cmd *cobra.Command) string {
	if pin := pinnedContext(); pin != "" {
		return pin
	}
	return flagContext(cmd)
}

// flagContext is what the command line names: --context, else --ctx.
func flagContext(cmd *cobra.Command) string {
	v, _ := cmd.Flags().GetString("context")
	if v != "" {
		return v
	}
	v, _ = cmd.Flags().GetString("ctx")
	return v
}

// contextEnv names the context every command in this process must use. A
// harness sets it so an agent's shell acts as that agent and nothing else.
const contextEnv = "TVAULT_CONTEXT"

func pinnedContext() string { return strings.TrimSpace(os.Getenv(contextEnv)) }

// pinnedCommands change which context is stored or active. Under a pin they
// are refused: the pin would still win for this shell, and the change would
// reach every other shell on the machine.
var pinnedCommands = map[string]bool{
	"tvault login":       true,
	"tvault logout":      true,
	"tvault context use": true,
	"tvault context rm":  true,
	"tvault use":         true,
	"tvault connect":     true,
}

// pinGuard is the root pre-run check for TVAULT_CONTEXT. Without the variable
// it does nothing.
func pinGuard(cmd *cobra.Command) error {
	pin := pinnedContext()
	if pin == "" {
		return nil
	}
	if flag := flagContext(cmd); flag != "" && flag != pin {
		return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(),
			Message: fmt.Sprintf("%s pins this shell to context %q, so --context %q is refused", contextEnv, pin, flag),
			Hint:    "Run the command without --context, or unset " + contextEnv + "."}
	}
	if pinnedCommands[cmd.CommandPath()] {
		return &clierr.CLIError{Kind: clierr.KindUser, Command: cmd.CommandPath(),
			Message: fmt.Sprintf("%s pins this shell to context %q, so contexts cannot be changed from it", contextEnv, pin),
			Hint:    "Unset " + contextEnv + " to sign in, sign out or switch contexts."}
	}
	return nil
}

func resolve(cmd *cobra.Command) (*cmdContext, error) {
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
		// A classic tvagent_ key on a management route gets a bare 401
		// "Invalid or expired token" (no code) from the server. That is not a
		// session expiry: classic agents can only read credentials.
		if cc != nil && cc.Ctx.Type == "agent" && ce.Kind == clierr.KindAuth && ce.Code == "" &&
			strings.HasPrefix(ce.Response, "401") &&
			!strings.HasSuffix(ce.Request, "/api/agents/credentials") &&
			!strings.HasSuffix(ce.Request, "/api/agents/whoami") {
			ce.Kind = clierr.KindHumanOnly
			ce.Message = "classic agents can only read credentials — use an admin context or a scoped agent"
			ce.Hint = "switch context with `tvault ctx use <admin-ctx>`, or create a scoped agent (`tvault agents create --kind scoped`)"
		}
		// A full policy explanation points at the console's policy list when
		// the frontend is known.
		if ce.Code == "POLICY_DENIED" && ce.Plain != "" && cc != nil && !strings.Contains(ce.Hint, "://") {
			if fe, ok := deriveFrontendURL(cc.Ctx.APIURL); ok {
				ce.Hint = strings.Replace(ce.Hint, "in the web app", "at "+fe+"/policies", 1)
			}
		}
		if ce.Kind == clierr.KindVaultLocked && ce.Hint == "" && cc != nil && cc.Ctx.Type == "admin" {
			ce.Hint = "tvault vault unlock"
		}
	}
	return err
}
