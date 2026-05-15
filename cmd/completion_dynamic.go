package cmd

import (
	"github.com/c-lgrant/tvault/internal/config"
	"github.com/spf13/cobra"
)

// completeServices suggests token service names for `<service>` arguments.
func completeServices(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	cc, err := resolve(cmd, false)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	toks, err := cc.Client.ListTokens()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var names []string
	for _, t := range toks {
		names = append(names, t.ServiceName)
	}
	return names, cobra.ShellCompDirectiveNoFileComp
}

// completeAgents suggests agent names for `<name-or-id>` arguments.
func completeAgents(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	cc, err := resolve(cmd, true)
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	agents, err := cc.Client.ListAgents()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var names []string
	for _, a := range agents {
		names = append(names, a.Name)
	}
	return names, cobra.ShellCompDirectiveNoFileComp
}

// completeAgentThenServices completes the first arg as an agent name and every
// subsequent arg as a token service name — the shape of `grants add/rm`.
func completeAgentThenServices(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) == 0 {
		return completeAgents(cmd, args, toComplete)
	}
	return completeServices(cmd, args, toComplete)
}

// completeContexts suggests stored context names.
func completeContexts(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	cfg, err := config.Load()
	if err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	var names []string
	for n := range cfg.Contexts {
		names = append(names, n)
	}
	return names, cobra.ShellCompDirectiveNoFileComp
}
