package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/output"
	"github.com/spf13/cobra"
)

// Labels tag credentials, agents and keys so a policy can attach to the label
// instead of to each object. A label never grants access; it only carries
// policies. Everything here is metadata: no credential value is involved.

var labelCmd = &cobra.Command{
	Use:   "label",
	Short: "Tag credentials, agents and keys with labels that policies attach to",
	Long: `Labels are short tags (1-32 lowercase letters, digits or hyphens) on credentials,
agents and keys. A policy attached to a label applies to every object that
carries it. A label never grants access: grants stay explicit.

Removing a label that has policies attached loosens those policies, so it needs
the policies:write scope (and a signed-in human for protected policies).`,
}

var labelLsCmd = &cobra.Command{
	Use:     "ls",
	Aliases: []string{"list"},
	Short:   "List labels with how many credentials, agents and keys carry each, and their policies",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolve(cmd)
		if err != nil {
			return err
		}
		labels, raw, err := cc.Client.ListLabels()
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if asJSON, _ := cmd.Flags().GetBool("json"); asJSON {
			var buf bytes.Buffer
			if err := json.Indent(&buf, raw, "", "  "); err != nil {
				return err
			}
			fmt.Println(buf.String())
			return nil
		}
		if len(labels) == 0 {
			cmd.PrintErrln("No labels. Add one with `tvault label add <kind> <id> <label>`.")
			return nil
		}
		rows := make([]map[string]string, len(labels))
		for i, l := range labels {
			rows[i] = map[string]string{
				"label":       l.Label,
				"credentials": strconv.Itoa(l.Credentials),
				"agents":      strconv.Itoa(l.Agents),
				"keys":        strconv.Itoa(l.Keys),
				"policies":    strings.Join(l.PolicyIDs, ","),
			}
		}
		return output.Render(os.Stdout, cc.Format,
			[]string{"label", "credentials", "agents", "keys", "policies"}, rows)
	},
}

var labelSetCmd = &cobra.Command{
	Use:   "set <credential|agent|key> <id> <label>...",
	Short: "Replace an object's labels with exactly these",
	Args:  cobra.MinimumNArgs(3),
	Example: `  tvault label set credential github prod finance
  tvault label set agent ci-bot prod`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runLabelChange(cmd, args, func(_ []string, given []string) []string { return given })
	},
}

var labelAddCmd = &cobra.Command{
	Use:   "add <credential|agent|key> <id> <label>...",
	Short: "Add labels to an object, keeping the ones it has",
	Args:  cobra.MinimumNArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runLabelChange(cmd, args, func(current, given []string) []string {
			return append(append([]string{}, current...), given...)
		})
	},
}

var labelRmCmd = &cobra.Command{
	Use:     "rm <credential|agent|key> <id> <label>...",
	Aliases: []string{"remove"},
	Short:   "Remove labels from an object",
	Long: `Removes labels from an object. If a removed label has policies attached, the
server needs the policies:write scope, and refuses a key or agent removing one
from itself or from a credential it holds (exit 8 for a missing scope).`,
	Args: cobra.MinimumNArgs(3),
	RunE: func(cmd *cobra.Command, args []string) error {
		return runLabelChange(cmd, args, func(current, given []string) []string {
			drop := map[string]bool{}
			for _, g := range given {
				drop[g] = true
			}
			var out []string
			for _, c := range current {
				if !drop[c] {
					out = append(out, c)
				}
			}
			return out
		})
	},
}

// labelKind maps the CLI's kind word to the wire entity type.
func labelKind(word string) (string, error) {
	switch strings.ToLower(word) {
	case "credential", "credentials", "cred", "token":
		return "credential", nil
	case "agent", "agents":
		return "agent", nil
	case "key", "keys", "api_key", "api-key":
		return "api_key", nil
	}
	return "", &clierr.CLIError{
		Kind:    clierr.KindUser,
		Message: fmt.Sprintf("unknown kind %q", word),
		Hint:    "use credential, agent or key",
	}
}

// normLabels trims and lower-cases labels as the server does and drops
// duplicates, keeping first occurrence.
func normLabels(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, l := range in {
		l = strings.ToLower(strings.TrimSpace(l))
		if l == "" || seen[l] {
			continue
		}
		seen[l] = true
		out = append(out, l)
	}
	return out
}

// resolveLabelTarget turns the user's reference into the wire kind and ID:
// agents and keys may be named by name or ID, credentials by service name.
func resolveLabelTarget(cc *cmdContext, kindWord, ref string) (kind, id string, err error) {
	kind, err = labelKind(kindWord)
	if err != nil {
		return "", "", err
	}
	switch kind {
	case "agent":
		rs, err := resolveAgents(cc.Client, []string{ref}, true)
		if err != nil {
			return "", "", err
		}
		return kind, rs[0].ID, nil
	case "api_key":
		r, err := resolveKey(cc.Client, ref, true)
		if err != nil {
			return "", "", err
		}
		return kind, r.ID, nil
	}
	return kind, ref, nil
}

// runLabelChange backs set/add/rm. next computes the new set from the current
// one (read from the object's list endpoint) and the labels given.
func runLabelChange(cmd *cobra.Command, args []string, next func(current, given []string) []string) error {
	cc, err := resolve(cmd)
	if err != nil {
		return err
	}
	kind, id, err := resolveLabelTarget(cc, args[0], args[1])
	if err != nil {
		return enrich(cmd, cc, err)
	}
	given := normLabels(args[2:])
	if len(given) == 0 {
		return enrich(cmd, cc, &clierr.CLIError{Kind: clierr.KindUser, Message: "no labels given"})
	}

	var target []string
	if cmd.Name() == "set" {
		target = next(nil, given)
	} else {
		current, found, err := cc.Client.CurrentLabels(kind, id)
		if err != nil {
			return enrich(cmd, cc, err)
		}
		if !found {
			return enrich(cmd, cc, &clierr.CLIError{
				Kind:    clierr.KindUser,
				Message: fmt.Sprintf("%s %q not found", strings.ReplaceAll(kind, "_", " "), id),
			})
		}
		current = normLabels(current)
		target = normLabels(next(current, given))
		if sameLabels(current, target) {
			cmd.PrintErrf("No change: %s %s already has these labels.\n", kind, id)
			printLabels(current)
			return nil
		}
	}

	res, err := cc.Client.PutLabels(kind, id, target)
	if err != nil {
		return enrich(cmd, cc, err)
	}
	if cc.Client.DryRun {
		return nil
	}
	if len(res.Labels) == 0 {
		cmd.PrintErrf("%s %s now has no labels.\n", kind, id)
	}
	for _, p := range res.Policies {
		name := p.ID
		if p.Name != nil && *p.Name != "" {
			name = *p.Name + " (" + p.ID + ")"
		}
		state := ""
		if !p.Enabled {
			state = " [disabled]"
		}
		cmd.PrintErrf("policy %s applies via label %q%s\n", name, p.Label, state)
	}
	printLabels(res.Labels)
	return nil
}

func sameLabels(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]bool{}
	for _, x := range a {
		set[x] = true
	}
	for _, y := range b {
		if !set[y] {
			return false
		}
	}
	return true
}

// printLabels writes the label set to stdout, one per line, for scripts.
func printLabels(labels []string) {
	for _, l := range labels {
		fmt.Println(l)
	}
}

// historyShortCmd is the top-level `tvault history <name>`: the same command
// as `tvault tokens history`.
var historyShortCmd = &cobra.Command{
	Use:               "history <name>",
	Short:             "Show a credential's usage history (same as `tvault tokens history`)",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeServices,
	RunE:              tokensHistoryCmd.RunE,
}

// credentialsCmd is the top-level `tvault credentials`: the same listing as
// `tvault tokens list` and `tvault list`.
var credentialsCmd = &cobra.Command{
	Use:     "credentials",
	Aliases: []string{"creds"},
	Short:   "List credentials (same as `tvault tokens list`)",
	Args:    cobra.NoArgs,
	RunE:    runTokensList,
}

func init() {
	labelCmd.AddCommand(labelLsCmd, labelSetCmd, labelAddCmd, labelRmCmd)
	rootCmd.AddCommand(labelCmd, historyShortCmd, credentialsCmd)
}
