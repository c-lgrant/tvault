package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	neturl "net/url"
	"os"
	"sort"
	"strings"

	"github.com/c-lgrant/tvault/internal/api"
	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/output"
	"github.com/spf13/cobra"
)

// tokenPlaceholder is the literal text the user's webhook replaces with the
// credential. It is metadata: the CLI never sees or sends a credential value.
const tokenPlaceholder = "${TOKEN}"

var mcpServersCmd = &cobra.Command{
	Use:     "mcp-servers",
	Aliases: []string{"mcp"},
	Short:   "Manage a credential's MCP servers",
	Long: `A credential can have up to five MCP servers attached. An agent granted
"tools" on the credential calls them through Token Vault and is never handed
the value: your webhook puts the credential into the request.

Header templates mark where the credential goes with the literal text ${TOKEN}.
Quote it so your shell does not expand it:  --header 'Authorization: Bearer ${TOKEN}'
Only the template is sent to Token Vault, never a credential value.`,
}

// mcpEndpoint is the per-server MCP URL an OAuth client or agent connects to.
func mcpEndpoint(apiURL, service, server string) string {
	return strings.TrimRight(apiURL, "/") + "/api/mcp/" + neturl.PathEscape(service) + "/" + neturl.PathEscape(server)
}

// mcpServerView is how `ls --format json` shows a server: the API fields plus
// the endpoint agents connect to.
type mcpServerView struct {
	api.MCPServer
	Endpoint string `json:"endpoint"`
}

func headerSummary(h map[string]string) string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + ": " + h[k]
	}
	return strings.Join(parts, "; ")
}

var mcpServersListCmd = &cobra.Command{
	Use:               "list <service>",
	Aliases:           []string{"ls"},
	Short:             "List a credential's MCP servers",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeServicesFirst,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		servers, err := cc.Client.ListMCPServers(args[0])
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if cc.Format == output.FormatJSON {
			views := make([]mcpServerView, len(servers))
			for i, s := range servers {
				if s.Headers == nil {
					s.Headers = map[string]string{}
				}
				views[i] = mcpServerView{s, mcpEndpoint(cc.Ctx.APIURL, args[0], s.Name)}
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(views)
		}
		if len(servers) == 0 {
			cmd.PrintErrf("No MCP servers. Add one with `tvault mcp-servers add %s --preset <id>` (see `tvault mcp-servers templates`).\n", args[0])
			return nil
		}
		rows := make([]map[string]string, len(servers))
		for i, s := range servers {
			url := s.URL
			if s.URLRedacted {
				url += " (path hidden)"
			}
			rows[i] = map[string]string{
				"name": s.Name, "url": url, "template": s.Template,
				"headers": headerSummary(s.Headers), "endpoint": mcpEndpoint(cc.Ctx.APIURL, args[0], s.Name),
			}
		}
		cols := []string{"name", "url", "template", "endpoint"}
		if cc.Format == output.FormatWide {
			cols = []string{"name", "url", "template", "headers", "endpoint"}
		}
		return output.Render(os.Stdout, cc.Format, cols, rows)
	},
}

var mcpServersTemplatesCmd = &cobra.Command{
	Use:   "templates",
	Short: "List the MCP server presets for `mcp-servers add --preset`",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		tpls, err := cc.Client.ListMCPTemplates()
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if cc.Format == output.FormatJSON {
			if tpls == nil {
				tpls = []api.MCPTemplate{}
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(tpls)
		}
		rows := make([]map[string]string, len(tpls))
		for i, t := range tpls {
			rows[i] = map[string]string{"id": t.ID, "name": t.Name, "url": t.URL, "headers": headerSummary(t.Headers), "docs": t.DocsURL}
		}
		cols := []string{"id", "name", "url"}
		if cc.Format == output.FormatWide {
			cols = []string{"id", "name", "url", "headers", "docs"}
		}
		return output.Render(os.Stdout, cc.Format, cols, rows)
	},
}

// parseHeaderFlags turns repeated "Name: value" flags into a map.
func parseHeaderFlags(raw []string, command string) (map[string]string, error) {
	out := map[string]string{}
	for _, h := range raw {
		name, value, ok := strings.Cut(h, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || name == "" {
			return nil, &clierr.CLIError{Kind: clierr.KindUser, Command: command,
				Message: fmt.Sprintf("invalid --header %q: expected 'Name: value'", safeText(h)),
				Hint:    "quote it so the shell keeps ${TOKEN} as typed: --header 'Authorization: Bearer ${TOKEN}'"}
		}
		out[name] = value
	}
	return out, nil
}

// buildMCPServer assembles the server to attach from a preset and/or flags.
// Flags override the preset per field; a --header replaces a preset header of
// the same name (case-insensitively).
func buildMCPServer(tpl *api.MCPTemplate, name, url string, headerFlags []string, command string) (api.MCPServer, error) {
	userErr := func(msg, hint string) (api.MCPServer, error) {
		return api.MCPServer{}, &clierr.CLIError{Kind: clierr.KindUser, Command: command, Message: msg, Hint: hint}
	}
	flagHeaders, err := parseHeaderFlags(headerFlags, command)
	if err != nil {
		return api.MCPServer{}, err
	}
	s := api.MCPServer{Name: name, URL: url, Headers: map[string]string{}}
	if tpl != nil {
		if s.Name == "" {
			s.Name = tpl.ID
		}
		if s.URL == "" {
			s.URL = tpl.URL
		}
		s.Template = tpl.ID
		for k, v := range tpl.Headers {
			s.Headers[k] = v
		}
	}
	for k, v := range flagHeaders {
		for existing := range s.Headers {
			if strings.EqualFold(existing, k) {
				delete(s.Headers, existing)
			}
		}
		s.Headers[k] = v
	}
	switch {
	case s.Name == "":
		return userErr("--name is required without --preset", "or pick a preset: `tvault mcp-servers templates`")
	case s.URL == "":
		return userErr("--url is required without --preset", "or pick a preset: `tvault mcp-servers templates`")
	}
	found := false
	for _, v := range s.Headers {
		found = found || strings.Contains(v, tokenPlaceholder)
	}
	if !found {
		return userErr("no header contains the literal "+tokenPlaceholder+", so the credential would not be sent anywhere",
			"add --header 'Authorization: Bearer ${TOKEN}' (single quotes: the shell must not expand it)")
	}
	return s, nil
}

// updateMCPServers reads a credential's servers, applies mutate and PUTs the
// whole list back (the API is a full replace). skipRead assumes no servers
// yet, for a dry run before the credential exists. A server list a key or
// agent reads is redacted (origin only, no headers), so writing it back would
// destroy the real one: those contexts may only start from an empty list.
func updateMCPServers(cmd *cobra.Command, cc *cmdContext, service string, skipRead bool,
	mutate func([]api.MCPServer) ([]api.MCPServer, error)) ([]api.MCPServer, error) {
	var stored []api.MCPServer
	err := withReauth(cmd, cc, func() error {
		var existing []api.MCPServer
		if !skipRead {
			var e error
			if existing, e = cc.Client.ListMCPServers(service); e != nil {
				return e
			}
		}
		if cc.Ctx.Type != "admin" && len(existing) > 0 {
			return &clierr.CLIError{Kind: clierr.KindHumanOnly, Command: cmd.CommandPath(),
				Message: "this context sees " + service + "'s MCP servers redacted (URL origin only, no headers), so changing the list would overwrite them",
				Hint:    "use an admin context: `tvault ctx use <admin-ctx>`"}
		}
		next, e := mutate(existing)
		if e != nil {
			return e
		}
		stored, e = cc.Client.PutMCPServers(service, next)
		return e
	})
	return stored, err
}

// upsertServer replaces the server with the same name, or appends.
func upsertServer(existing []api.MCPServer, s api.MCPServer) []api.MCPServer {
	out := make([]api.MCPServer, 0, len(existing)+1)
	replaced := false
	for _, e := range existing {
		if e.Name == s.Name {
			out = append(out, s)
			replaced = true
		} else {
			out = append(out, e)
		}
	}
	if !replaced {
		out = append(out, s)
	}
	return out
}

// presetByID fetches the presets and returns the one called id.
func presetByID(cc *cmdContext, id, command string) (*api.MCPTemplate, error) {
	tpls, err := cc.Client.ListMCPTemplates()
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(tpls))
	for i := range tpls {
		if tpls[i].ID == id {
			return &tpls[i], nil
		}
		ids[i] = tpls[i].ID
	}
	return nil, &clierr.CLIError{Kind: clierr.KindUser, Command: command,
		Message: fmt.Sprintf("unknown preset %q (known: %s)", safeText(id), strings.Join(ids, ", ")),
		Hint:    "list presets with `tvault mcp-servers templates`, or pass --name/--url/--header yourself"}
}

var mcpServersAddCmd = &cobra.Command{
	Use:   "add <service> (--preset <id> | --name <name> --url <url> --header 'Name: value'...)",
	Short: "Attach an MCP server to a credential",
	Long: `Attaches an MCP server to a credential (reads the current list, adds or
replaces the server of that name, writes the whole list back).

Use --preset for a known upstream (` + "`tvault mcp-servers templates`" + `), or give
--name, --url and one or more --header. The credential goes in with the literal
text ${TOKEN}: quote it so your shell does not expand it. Only the template is
sent to Token Vault; your webhook substitutes the credential.

Adding a server, or changing a URL or headers, needs a recent sign-in. In an
interactive admin context the browser login opens and the command retries once.`,
	Example: `  tvault mcp-servers add github --preset github
  tvault mcp-servers add github --name docs --url https://mcp.example.com/mcp \
      --header 'Authorization: Bearer ${TOKEN}' --header 'Accept: application/json, text/event-stream'`,
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeServicesFirst,
	RunE: func(cmd *cobra.Command, args []string) error {
		preset, _ := cmd.Flags().GetString("preset")
		name, _ := cmd.Flags().GetString("name")
		url, _ := cmd.Flags().GetString("url")
		headers, _ := cmd.Flags().GetStringArray("header")
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		server, err := serverFromFlags(cc, preset, name, url, headers, "mcp-servers add")
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if _, err := updateMCPServers(cmd, cc, args[0], false, func(existing []api.MCPServer) ([]api.MCPServer, error) {
			return upsertServer(existing, server), nil
		}); err != nil {
			return enrich(cmd, cc, err)
		}
		if !cc.Client.DryRun {
			cmd.PrintErrf("Attached MCP server %q to %s.\n  endpoint: %s\n  grant an agent: tvault grant <agent> %s=tools:%s\n",
				server.Name, args[0], mcpEndpoint(cc.Ctx.APIURL, args[0], server.Name), args[0], server.Name)
		}
		return nil
	},
}

// serverFromFlags resolves --preset (fetching the preset) and builds the server.
func serverFromFlags(cc *cmdContext, preset, name, url string, headers []string, command string) (api.MCPServer, error) {
	var tpl *api.MCPTemplate
	if preset != "" {
		var err error
		if tpl, err = presetByID(cc, preset, command); err != nil {
			return api.MCPServer{}, err
		}
	}
	return buildMCPServer(tpl, name, url, headers, command)
}

var mcpServersRmCmd = &cobra.Command{
	Use:     "rm <service> <name>",
	Aliases: []string{"remove"},
	Short:   "Detach an MCP server from a credential",
	Long: `Detaches an MCP server (reads the current list, drops the one named, writes
the rest back). Grants that name the server are not edited; they keep the
stale name and the server answers "not found" until one of that name is added.`,
	Args: cobra.ExactArgs(2),
	ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 0 {
			return completeServices(cmd, args, toComplete)
		}
		if len(args) > 1 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		cc, err := resolve(cmd)
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		servers, err := cc.Client.ListMCPServers(args[0])
		if err != nil {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		names := make([]string, len(servers))
		for i, s := range servers {
			names[i] = s.Name
		}
		return names, cobra.ShellCompDirectiveNoFileComp
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		force, _ := cmd.Flags().GetBool("force")
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		if !confirmDestructive(cmd, cc, "detach MCP server", []string{args[1], "from " + args[0]}, force) {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "mcp-servers rm", Message: "aborted"}
		}
		_, err = updateMCPServers(cmd, cc, args[0], false, func(existing []api.MCPServer) ([]api.MCPServer, error) {
			next := make([]api.MCPServer, 0, len(existing))
			for _, s := range existing {
				if s.Name != args[1] {
					next = append(next, s)
				}
			}
			if len(next) == len(existing) {
				return nil, &clierr.CLIError{Kind: clierr.KindUser, Command: "mcp-servers rm",
					Message: fmt.Sprintf("%s has no MCP server named %q", safeText(args[0]), safeText(args[1])),
					Hint:    "list them with `tvault mcp-servers ls " + args[0] + "`"}
			}
			return next, nil
		})
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if !cc.Client.DryRun {
			cmd.PrintErrf("Detached MCP server %q from %s.\n", args[1], args[0])
		}
		return nil
	},
}

// completeServicesFirst completes the first argument only.
func completeServicesFirst(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	return completeServices(cmd, args, toComplete)
}

// attachMCPPreset attaches the preset server to a freshly stored credential
// (`tvault add --mcp`). The value is already stored, so a failure here keeps
// the credential and tells the user how to retry. The error keeps the
// original kind (and so the exit code).
func attachMCPPreset(cmd *cobra.Command, cc *cmdContext, service string, tpl *api.MCPTemplate) error {
	server, err := buildMCPServer(tpl, "", "", nil, "add")
	if err != nil {
		return err
	}
	retry := fmt.Sprintf("tvault mcp-servers add %s --preset %s", service, tpl.ID)
	// A dry run stored nothing, so there is no credential to read servers from.
	_, err = updateMCPServers(cmd, cc, service, cc.Client.DryRun, func(existing []api.MCPServer) ([]api.MCPServer, error) {
		return upsertServer(existing, server), nil
	})
	if err != nil {
		out := &clierr.CLIError{Kind: clierr.KindUser}
		var ce *clierr.CLIError
		if errors.As(err, &ce) {
			c := *ce
			out = &c
		}
		out.Command = "add"
		out.Message = fmt.Sprintf("the credential %s is stored, but attaching the %s MCP server failed: %s", service, tpl.ID, api.BriefError(err))
		out.Hint = "the value stays stored; retry with: " + retry
		return out
	}
	if !cc.Client.DryRun {
		cmd.PrintErrf("Attached MCP server %q to %s.\n  endpoint: %s\n", server.Name, service, mcpEndpoint(cc.Ctx.APIURL, service, server.Name))
	}
	return nil
}

func init() {
	mcpServersAddCmd.Flags().String("preset", "", "start from a preset (see `tvault mcp-servers templates`)")
	mcpServersAddCmd.Flags().String("name", "", "server name: lowercase letters, digits, - or _ (defaults to the preset id)")
	mcpServersAddCmd.Flags().String("url", "", "upstream https URL (overrides the preset's)")
	mcpServersAddCmd.Flags().StringArray("header", nil, "header template 'Name: value'; use the literal ${TOKEN} (single-quote it); repeatable")
	mcpServersRmCmd.Flags().Bool("force", false, "skip the confirmation prompt")
	mcpServersCmd.AddCommand(mcpServersListCmd, mcpServersAddCmd, mcpServersRmCmd, mcpServersTemplatesCmd)
	rootCmd.AddCommand(mcpServersCmd)
}
