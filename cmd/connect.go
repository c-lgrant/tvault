package cmd

import (
	"bufio"
	"errors"
	"fmt"
	neturl "net/url"
	"os"
	"os/exec"
	"strings"

	"github.com/c-lgrant/tvault/internal/api"
	"github.com/c-lgrant/tvault/internal/auth"
	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/config"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Seams for tests.
var (
	// reauthLogin runs the browser login for cc's admin context and swaps
	// cc.Client for one holding the fresh session.
	reauthLogin = reauthViaBrowser
	// claudeLookPath finds the Claude Code CLI.
	claudeLookPath = func() (string, error) { return exec.LookPath("claude") }
	// claudeRun runs `claude <args...>` with its output on stderr (stdout is
	// reserved for values); it returns the process error, if any.
	// stderrIsTTY says whether a person is watching: the re-sign-in needs a
	// browser, not stdin, so a piped stdin must not rule it out.
	stderrIsTTY = func() bool { return term.IsTerminal(int(os.Stderr.Fd())) }
	// loginFn is the browser login.
	loginFn = auth.Login
	// claudeGet runs `claude mcp get <name>` and returns its output.
	claudeGet = func(name string) (string, error) {
		out, err := exec.Command("claude", "mcp", "get", name).CombinedOutput()
		return string(out), err
	}
	claudeRun = func(args ...string) error {
		c := exec.Command("claude", args...)
		c.Stdout, c.Stderr, c.Stdin = os.Stderr, os.Stderr, os.Stdin
		return c.Run()
	}
)

func isReauthRequired(err error) bool {
	var ce *clierr.CLIError
	return errors.As(err, &ce) && ce.Code == "REAUTH_REQUIRED"
}

// withReauth runs fn (which must use cc.Client at call time). If the server
// answers REAUTH_REQUIRED and the context is an interactive admin login, it
// signs in again through the browser flow and retries fn once. Key and agent
// contexts, and non-interactive shells, keep the plain error.
func withReauth(cmd *cobra.Command, cc *cmdContext, fn func() error) error {
	err := fn()
	if !isReauthRequired(err) || cc.Ctx.Type != "admin" || !stderrIsTTY() {
		return err
	}
	cmd.PrintErrln("This action needs a fresh sign-in. Opening the browser login...")
	if lerr := reauthLogin(cmd, cc); lerr != nil {
		return lerr
	}
	return fn()
}

// reauthViaBrowser is the same flow as `tvault login` for cc's context name
// and API URL; it then reloads the session into cc.
func reauthViaBrowser(cmd *cobra.Command, cc *cmdContext) error {
	apiURL := cc.Ctx.APIURL
	frontend := defaultFrontendURL
	if strings.TrimRight(apiURL, "/") != defaultAPIURL {
		var ok bool
		if frontend, ok = deriveFrontendURL(apiURL); !ok {
			return &clierr.CLIError{Kind: clierr.KindAuth, Command: cmd.CommandPath(),
				Message: "this action needs a fresh sign-in, but the frontend URL for " + apiURL + " can't be derived",
				Hint:    "run `tvault login --api-url " + apiURL + " --frontend-url <url> --as " + cc.ContextName + "`, then retry"}
		}
	}
	prev, err := config.Load()
	if err != nil {
		return err
	}
	if err := loginFn(auth.LoginOptions{
		ContextName: cc.ContextName, APIURL: apiURL, FrontendURL: frontend,
	}); err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	// The browser may have signed in as someone else. Login already replaced
	// the stored context, so put the original back and refuse to retry.
	if nc := cfg.Contexts[cc.ContextName]; nc != nil && cc.Ctx.Identity != "" &&
		!strings.EqualFold(nc.Identity, cc.Ctx.Identity) {
		if old := prev.Contexts[cc.ContextName]; old != nil {
			cfg.Contexts[cc.ContextName] = old
		}
		cfg.Current = prev.Current
		_ = cfg.Save()
		return &clierr.CLIError{Kind: clierr.KindAuth, Command: cmd.CommandPath(),
			Message: fmt.Sprintf("signed in as %s, but context %q belongs to %s; nothing was changed",
				safeText(nc.Identity), cc.ContextName, safeText(cc.Ctx.Identity)),
			Hint: "sign in with the same account, or log in again under a different context name (`tvault login --as <name>`)"}
	}
	if cfg.Current != prev.Current { // keep the user's active context
		cfg.Current = prev.Current
		if err := cfg.Save(); err != nil {
			return err
		}
	}
	ctx := cfg.Contexts[cc.ContextName]
	if ctx == nil {
		return &clierr.CLIError{Kind: clierr.KindAuth, Command: cmd.CommandPath(), Message: "context " + cc.ContextName + " is gone after login"}
	}
	debug, _ := cmd.Flags().GetBool("debug")
	client, err := auth.ClientFor(ctx, debug)
	if err != nil {
		return err
	}
	client.DryRun = cc.Client.DryRun
	cc.Client, cc.Ctx = client, ctx
	return nil
}

// askYesNo prompts on stderr and reads one line from the command's stdin.
func askYesNo(cmd *cobra.Command, prompt string) bool {
	cmd.PrintErr(prompt)
	line, _ := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	a := strings.ToLower(strings.TrimSpace(line))
	return a == "y" || a == "yes"
}

// ensureAgent resolves an agent by name or ID, creating it (after a y/N
// prompt, or with yes) when no such agent exists. The new agent's API key is
// not printed: these flows connect the agent through MCP sign-in, and the key
// can be minted later with `tvault agents rotate-key`.
func ensureAgent(cmd *cobra.Command, cc *cmdContext, ref, command string, yes bool) (resolved, error) {
	rs, err := resolveAgents(cc.Client, []string{ref}, true)
	if err != nil {
		return resolved{}, err
	}
	// pickRef passes an unmatched ref through with no name; an ID-shaped ref
	// is trusted as an ID (listing may be denied), anything else is a miss.
	if rs[0].Name != "" || agentIDPattern.MatchString(ref) {
		// The agent can't be used from Claude Code while MCP is off for it.
		// Best effort: a denied lookup or an older server stays silent.
		if a, gerr := cc.Client.GetAgent(rs[0].ID); gerr == nil && a.MCPEnabled != nil && !*a.MCPEnabled {
			cmd.PrintErrf("warning: MCP is turned off for agent %s, so Claude Code will not be able to use it. Turn it on in the console.\n", rs[0].label())
		}
		return rs[0], nil
	}
	if !yes {
		if !stdinIsTTY() {
			return resolved{}, &clierr.CLIError{Kind: clierr.KindUser, Command: command,
				Message: fmt.Sprintf("agent %s does not exist, and this shell is not interactive", safeText(ref)),
				Hint:    "re-run with --yes to create it"}
		}
		if !askYesNo(cmd, fmt.Sprintf("Create agent %q? [y/N] ", safeText(ref))) {
			return resolved{}, &clierr.CLIError{Kind: clierr.KindUser, Command: command, Message: "aborted"}
		}
	}
	var res *api.CreateAgentResult
	err = withReauth(cmd, cc, func() (e error) {
		res, e = cc.Client.CreateAgent(ref)
		return e
	})
	if err != nil {
		return resolved{}, err
	}
	if cc.Client.DryRun {
		res.ID = "<new-agent-id>"
	}
	cmd.PrintErrf("Created agent %q.\n", ref)
	return resolved{ID: res.ID, Name: ref}, nil
}

func grantSpecs(cmd *cobra.Command, cc *cmdContext, agent resolved, specs []api.GrantSpec, command string) error {
	if len(specs) == 0 {
		return nil
	}
	res := cc.Client.AddGrantSpecs(agent.ID, specs)
	if err := res.Err(); err != nil {
		kind := clierr.KindUser
		for _, e := range res.Failed {
			var ce *clierr.CLIError
			if errors.As(e, &ce) {
				kind = ce.Kind
				break
			}
		}
		return &clierr.CLIError{Kind: kind, Command: command, Context: cc.label(),
			Message: "granting services to " + agent.label() + " failed: " + err.Error()}
	}
	cmd.PrintErrf("Granted %s to %s.\n", strings.Join(res.OK, ", "), agent.label())
	return nil
}

var connectCmd = &cobra.Command{
	Use:   "connect <agent> [<service>[=<uses>[:<server>,...]]...]",
	Short: "Grant services to an agent (creating it if needed) and print how to connect Claude Code",
	Long: `Grants existing credentials to an agent, creating the agent first if it does
not exist, then registers Token Vault as an MCP server in Claude Code.

A service can carry what the grant is for, as in ` + "`tvault grant`" + `:
github=tools, github=value,tools:github (see ` + "`tvault grant --help`" + `).

With --server <service>/<server>, the one credential MCP server (see
` + "`tvault mcp-servers`" + `) is added to Claude Code as its own entry instead of the
general Token Vault one: ` + "`claude mcp add --transport http --scope user <name> <url>`" + `
with the per-server URL <api>/api/mcp/<service>/<server>. The entry name
defaults to tv-<service>-<server>; override it with --name.

The credential values never pass through Token Vault; this only creates the
agent and its grants. In Claude Code, run /mcp, sign in, and pick the agent.`,
	Example: `  tvault connect my-agent github stripe
  tvault connect my-agent github --yes --no-claude
  tvault connect my-agent github=tools:github --server github/github`,
	Args:              cobra.MinimumNArgs(1),
	ValidArgsFunction: completeAgentThenServices,
	RunE:              runConnect,
}

func runConnect(cmd *cobra.Command, args []string) error {
	yes, _ := cmd.Flags().GetBool("yes")
	noClaude, _ := cmd.Flags().GetBool("no-claude")
	printOnly, _ := cmd.Flags().GetBool("print")
	serverRef, _ := cmd.Flags().GetString("server")
	entryName, _ := cmd.Flags().GetString("name")

	var svc, srv string
	if serverRef != "" {
		var ok bool
		if svc, srv, ok = splitServerRef(serverRef); !ok {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "connect",
				Message: fmt.Sprintf("invalid --server %q: expected <service>/<server>", safeText(serverRef)),
				Hint:    "list a credential's servers with `tvault mcp-servers ls <service>`"}
		}
	} else if entryName != "" {
		return &clierr.CLIError{Kind: clierr.KindUser, Command: "connect", Message: "--name only applies with --server"}
	}
	specs, err := parseGrantSpecs(args[1:], "connect")
	if err != nil {
		return err
	}

	cc, err := resolve(cmd)
	if err != nil {
		return err
	}
	agent, err := ensureAgent(cmd, cc, args[0], "connect", yes)
	if err != nil {
		return enrich(cmd, cc, err)
	}
	if err := grantSpecs(cmd, cc, agent, specs, "connect"); err != nil {
		return enrich(cmd, cc, err)
	}

	if serverRef != "" {
		if !hasToolsGrant(specs, svc, srv) {
			cmd.PrintErrf("note: %s needs a tools grant on %s to call this server: tvault grant %s %s=tools:%s\n",
				agent.label(), safeText(svc), safeText(args[0]), safeText(svc), safeText(srv))
		}
		if !noClaude {
			if entryName == "" {
				entryName = "tv-" + svc + "-" + srv
			}
			url := strings.TrimRight(cc.Ctx.APIURL, "/") + "/api/mcp/" + neturl.PathEscape(svc) + "/" + neturl.PathEscape(srv)
			registerEntryWithClaude(cmd, cc, printOnly, entryName, url)
		}
	} else if !noClaude {
		registerWithClaude(cmd, cc, printOnly)
	}
	name := agent.Name
	if name == "" {
		name = agent.ID
	}
	cmd.PrintErrf("In Claude Code, run /mcp, sign in, and pick %s.\n", safeText(name))
	return nil
}

// registerWithClaude adds Token Vault as an MCP server in Claude Code when
// it is not registered yet. Problems here never fail the command: the agent
// and grants already exist, so the manual command is printed instead.
func registerWithClaude(cmd *cobra.Command, cc *cmdContext, printOnly bool) {
	registerEntryWithClaude(cmd, cc, printOnly, "tokenvault", strings.TrimRight(cc.Ctx.APIURL, "/")+"/api/agents/mcp")
}

// splitServerRef parses a --server value, <service>/<server>.
func splitServerRef(ref string) (svc, srv string, ok bool) {
	svc, srv, ok = strings.Cut(ref, "/")
	if !ok || svc == "" || srv == "" || strings.Contains(srv, "/") {
		return "", "", false
	}
	return svc, srv, true
}

// hasToolsGrant reports whether specs already give a tools grant on svc that
// covers server (no server list = every server).
func hasToolsGrant(specs []api.GrantSpec, svc, server string) bool {
	for _, s := range specs {
		if s.Service != svc {
			continue
		}
		tools := false
		for _, u := range s.Uses {
			tools = tools || u == "tools"
		}
		if !tools {
			continue
		}
		if len(s.Servers) == 0 {
			return true
		}
		for _, n := range s.Servers {
			if n == server {
				return true
			}
		}
	}
	return false
}

// registerEntryWithClaude adds one HTTP MCP server entry called name at mcpURL.
func registerEntryWithClaude(cmd *cobra.Command, cc *cmdContext, printOnly bool, name, mcpURL string) {
	add := []string{"mcp", "add", "--transport", "http", "--scope", "user", name, mcpURL}
	line := "claude " + strings.Join(add, " ")
	what := "Token Vault"
	if name != "tokenvault" {
		what = "the " + name + " MCP server"
	}
	if printOnly || cc.Client.DryRun {
		cmd.PrintErrf("To register %s with Claude Code, run:\n  %s\n", what, line)
		return
	}
	if _, err := claudeLookPath(); err != nil {
		cmd.PrintErrf("Claude Code (`claude`) is not on PATH. To register %s later, run:\n  %s\n", what, line)
		return
	}
	if out, err := claudeGet(name); err == nil {
		if strings.Contains(out, mcpURL) {
			cmd.PrintErrf("Claude Code already has a %q MCP server for this control plane.\n", name)
			return
		}
		// Registered, but pointing somewhere else (another environment).
		// Replacing it is the user's call, so only print the commands.
		cmd.PrintErrf("Claude Code already has a %q MCP server, but not for %s.\nTo switch it, run:\n  claude mcp remove %s\n  %s\n", name, mcpURL, name, line)
		return
	}
	cmd.PrintErrf("Registering %s with Claude Code:\n  %s\n", what, line)
	if err := claudeRun(add...); err != nil {
		cmd.PrintErrf("That command failed (%v). Run it yourself to finish registering.\n", err)
	}
}

func init() {
	connectCmd.Flags().Bool("yes", false, "create the agent without asking if it does not exist")
	connectCmd.Flags().Bool("no-claude", false, "do not look for or touch Claude Code")
	connectCmd.Flags().Bool("print", false, "only print the `claude mcp add` command; run nothing")
	connectCmd.Flags().String("server", "", "add one credential MCP server (<service>/<server>) to Claude Code as its own entry, instead of the general Token Vault one")
	connectCmd.Flags().String("name", "", "with --server: the Claude Code entry name (default tv-<service>-<server>)")
	rootCmd.AddCommand(connectCmd)
}
