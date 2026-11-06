package cmd

import (
	"errors"
	"fmt"
	"strings"

	"github.com/c-lgrant/tvault/internal/api"
	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/spf13/cobra"
)

// defaultSignInServerName is the MCP server name used by `add --sign-in` when
// --server is not given.
const defaultSignInServerName = "mcp"

// signInHeader is the header a sign-in MCP server gets by default: Token Vault
// puts the calling agent's short pass where ${AGENT_SESSION} is.
const signInHeader = "Authorization: Bearer " + agentSessionPlaceholder

// runAddSignIn implements `tvault add <name> --sign-in <url>`: it creates a
// "Token Vault sign-in" credential (no value), attaches the MCP server at url,
// then grants MCP access to each --for agent. Nothing here reads or sends a value.
func runAddSignIn(cmd *cobra.Command, name, url string, forFlags []string) error {
	fail := func(msg, hint string) error {
		return &clierr.CLIError{Kind: clierr.KindUser, Command: "add", Message: msg, Hint: hint}
	}
	for _, f := range []string{"value", "value-stdin", "type", "mcp"} {
		if cmd.Flags().Changed(f) {
			return fail("--"+f+" cannot be combined with --sign-in: a Token Vault sign-in credential has no value",
				"see `tvault explain SIGNIN_NO_VALUE`")
		}
	}
	if !strings.HasPrefix(strings.ToLower(url), "https://") {
		return fail(fmt.Sprintf("--sign-in needs the https URL of your MCP server, got %q", safeText(url)), "")
	}
	serverName, _ := cmd.Flags().GetString("server")
	if serverName == "" {
		serverName = defaultSignInServerName
	}
	server, err := buildMCPServer(nil, serverName, url, []string{signInHeader}, "add")
	if err != nil {
		return err
	}

	// Each --for is one agent; a sign-in credential can only be granted for
	// MCP access, so a plain --for means mcp and any value use is refused here,
	// before anything is created.
	type target struct {
		ref, arg string
		specs    []api.GrantSpec
		agent    resolved
	}
	targets := make([]*target, 0, len(forFlags))
	for _, f := range forFlags {
		ref, grantArg := splitForFlag(f, name)
		if !strings.Contains(grantArg, "=") {
			grantArg += "=mcp"
		}
		spec, err := parseGrantSpec(grantArg, "add")
		if err != nil {
			return err
		}
		for _, u := range spec.Uses {
			if u == "value" {
				return fail(fmt.Sprintf("%s is a Token Vault sign-in credential, so it can only be granted MCP access (not value)", safeText(name)),
					fmt.Sprintf("use --for %s=mcp; see `tvault explain SIGNIN_TOOLS_ONLY`", safeText(ref)))
			}
		}
		targets = append(targets, &target{ref: ref, arg: grantArg, specs: []api.GrantSpec{spec}})
	}

	yes, _ := cmd.Flags().GetBool("yes")
	cc, err := resolve(cmd)
	if err != nil {
		return err
	}
	// Settle the agents first so a refused agent never leaves a half-made credential.
	for _, tg := range targets {
		if tg.agent, err = ensureAgent(cmd, cc, tg.ref, "add", yes); err != nil {
			return enrich(cmd, cc, err)
		}
	}

	if err := cc.Client.CreateSignIn(name); err != nil {
		return enrich(cmd, cc, err)
	}
	if !cc.Client.DryRun {
		cmd.PrintErrf("Created Token Vault sign-in credential %q (no value stored).\n", name)
	}

	retry := fmt.Sprintf("tvault mcp-servers add %s --name %s --url %s --header '%s'", name, serverName, url, signInHeader)
	_, err = updateMCPServers(cmd, cc, name, cc.Client.DryRun, func(existing []api.MCPServer) ([]api.MCPServer, error) {
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
		out.Message = fmt.Sprintf("the sign-in credential %s is created, but attaching its MCP server failed: %s", name, api.BriefError(err))
		out.Hint = "retry with: " + retry
		for _, tg := range targets {
			out.Hint += fmt.Sprintf(", then: tvault grant %s %s", tg.ref, tg.arg)
		}
		return enrich(cmd, cc, out)
	}
	if !cc.Client.DryRun {
		cmd.PrintErrf("Attached MCP server %q to %s.\n  endpoint: %s\n", server.Name, name, mcpEndpoint(cc.Ctx.APIURL, name, server.Name))
	}

	var firstErr error
	for _, tg := range targets {
		if err := grantSpecs(cmd, cc, tg.agent, tg.specs, "add"); err != nil {
			if firstErr == nil {
				firstErr = enrich(cmd, cc, err)
			} else {
				cmd.PrintErrln(err)
			}
		}
	}
	return firstErr
}
