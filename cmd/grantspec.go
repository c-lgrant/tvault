package cmd

import (
	"fmt"
	"strings"

	"github.com/c-lgrant/tvault/internal/api"
	"github.com/c-lgrant/tvault/internal/clierr"
)

// grantSpecSyntax is shown in help text and parse errors.
const grantSpecSyntax = "<service>[=<uses>[:<server>,<server>]]"

// parseGrantSpec reads one grant argument:
//
//	github                     value grant (today's meaning)
//	github=tools               tools grant, every MCP server of the credential
//	github=value,tools         both
//	github=tools:github,docs   tools grant limited to the named servers
//
// <uses> is a comma list of "value" and "tools"; the servers after ":" are
// valid only with tools. Names are checked again by the server.
func parseGrantSpec(arg, command string) (api.GrantSpec, error) {
	bad := func(msg string) (api.GrantSpec, error) {
		return api.GrantSpec{}, &clierr.CLIError{Kind: clierr.KindUser, Command: command,
			Message: fmt.Sprintf("invalid grant %q: %s", safeText(arg), msg),
			Hint:    "expected " + grantSpecSyntax + ", e.g. github=tools or github=value,tools:github"}
	}
	svc, rest, hasUses := strings.Cut(arg, "=")
	if svc == "" {
		return bad("missing service name")
	}
	spec := api.GrantSpec{Service: svc}
	if !hasUses {
		return spec, nil
	}
	usesPart, serversPart, hasServers := strings.Cut(rest, ":")
	seen := map[string]bool{}
	for _, u := range strings.Split(usesPart, ",") {
		u = strings.TrimSpace(u)
		if u != "value" && u != "tools" {
			return bad(fmt.Sprintf("uses must be \"value\" and/or \"tools\", got %q", safeText(u)))
		}
		if !seen[u] {
			seen[u] = true
			spec.Uses = append(spec.Uses, u)
		}
	}
	if hasServers {
		if !seen["tools"] {
			return bad("servers can only be named with tools")
		}
		for _, s := range strings.Split(serversPart, ",") {
			s = strings.TrimSpace(s)
			if s == "" {
				return bad("empty server name")
			}
			spec.Servers = append(spec.Servers, s)
		}
	}
	return spec, nil
}

func parseGrantSpecs(args []string, command string) ([]api.GrantSpec, error) {
	specs := make([]api.GrantSpec, 0, len(args))
	for _, a := range args {
		s, err := parseGrantSpec(a, command)
		if err != nil {
			return nil, err
		}
		specs = append(specs, s)
	}
	return specs, nil
}

// splitForFlag splits `--for <agent>[=<uses>[:<servers>]]` into the agent and
// the grant spec for service. An agent name never contains "=".
func splitForFlag(value, service string) (agent string, spec string) {
	agent, rest, ok := strings.Cut(value, "=")
	if !ok {
		return agent, service
	}
	return agent, service + "=" + rest
}
