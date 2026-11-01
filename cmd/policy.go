package cmd

import (
	"github.com/c-lgrant/tvault/internal/api"
	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/spf13/cobra"
)

var policyCmd = &cobra.Command{
	Use:     "policy",
	Aliases: []string{"policies"},
	Short:   "Attach and detach policies",
	Long: `Attach an existing policy to a label, credential, agent or key. A policy on a
label applies to every object carrying that label (see ` + "`tvault label --help`" + `).
Policies themselves are created in the web console.`,
}

var policyAttachCmd = &cobra.Command{
	Use:   "attach <policyId> [--label L]... [--credential C]... [--agent A]... [--key K]...",
	Short: "Attach a policy to labels, credentials, agents or keys",
	Args:  cobra.ExactArgs(1),
	Example: `  tvault policy attach pol_123 --label prod
  tvault policy attach pol_123 --agent ci-bot --credential github`,
	RunE: func(cmd *cobra.Command, args []string) error { return runPolicyAttachment(cmd, args[0], true) },
}

var policyDetachCmd = &cobra.Command{
	Use:   "detach <policyId> [--label L]... [--credential C]... [--agent A]... [--key K]...",
	Short: "Detach a policy from labels, credentials, agents or keys",
	Long: `Detaching loosens the controls on whatever it names, so the server needs
policies:write, and a signed-in human for protected policies.`,
	Args:    cobra.ExactArgs(1),
	RunE:    func(cmd *cobra.Command, args []string) error { return runPolicyAttachment(cmd, args[0], false) },
	Example: `  tvault policy detach pol_123 --label prod`,
}

func runPolicyAttachment(cmd *cobra.Command, policyID string, attach bool) error {
	labelsIn, _ := cmd.Flags().GetStringSlice("label")
	creds, _ := cmd.Flags().GetStringSlice("credential")
	agents, _ := cmd.Flags().GetStringSlice("agent")
	keys, _ := cmd.Flags().GetStringSlice("key")
	if len(labelsIn)+len(creds)+len(agents)+len(keys) == 0 {
		return &clierr.CLIError{Kind: clierr.KindUser, Message: "name something to " + verbWord(attach) + ": use --label, --credential, --agent or --key"}
	}
	cc, err := resolve(cmd)
	if err != nil {
		return err
	}
	var atts []api.PolicyAttachment
	for _, l := range normLabels(labelsIn) {
		atts = append(atts, api.PolicyAttachment{EntityType: "label", EntityID: l})
	}
	for _, c := range creds {
		atts = append(atts, api.PolicyAttachment{EntityType: "token", EntityID: c})
	}
	if len(agents) > 0 {
		rs, err := resolveAgents(cc.Client, agents, true)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		for _, r := range rs {
			atts = append(atts, api.PolicyAttachment{EntityType: "agent", EntityID: r.ID})
		}
	}
	for _, k := range keys {
		r, err := resolveKey(cc.Client, k, true)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		atts = append(atts, api.PolicyAttachment{EntityType: "api_key", EntityID: r.ID})
	}
	if attach {
		err = cc.Client.AttachPolicy(policyID, atts)
	} else {
		err = cc.Client.DetachPolicy(policyID, atts)
	}
	if err != nil {
		return enrich(cmd, cc, err)
	}
	if !cc.Client.DryRun {
		cmd.PrintErrf("%s policy %s (%d target(s)).\n", map[bool]string{true: "Attached", false: "Detached"}[attach], policyID, len(atts))
	}
	return nil
}

func verbWord(attach bool) string {
	if attach {
		return "attach to"
	}
	return "detach from"
}

func init() {
	for _, c := range []*cobra.Command{policyAttachCmd, policyDetachCmd} {
		c.Flags().StringSlice("label", nil, "a label (repeatable)")
		c.Flags().StringSlice("credential", nil, "a credential name (repeatable)")
		c.Flags().StringSlice("agent", nil, "an agent name or id (repeatable)")
		c.Flags().StringSlice("key", nil, "a key name or id (repeatable)")
	}
	policyCmd.AddCommand(policyAttachCmd, policyDetachCmd)
	rootCmd.AddCommand(policyCmd)
}
