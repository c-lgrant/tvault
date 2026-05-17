package cmd

import (
	"fmt"
	"sort"

	"github.com/c-lgrant/tvault/internal/clierr"
	"github.com/c-lgrant/tvault/internal/config"
	"github.com/spf13/cobra"
)

var contextCmd = &cobra.Command{
	Use:     "context",
	Aliases: []string{"ctx"},
	Short:   "Manage stored contexts (personas)",
}

var contextListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List stored contexts",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		if len(cfg.Contexts) == 0 {
			cmd.PrintErrln("No contexts. Run `tvault login` to create one.")
			return nil
		}
		names := make([]string, 0, len(cfg.Contexts))
		for n := range cfg.Contexts {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			marker := "  "
			if n == cfg.Current {
				marker = "* "
			}
			c := cfg.Contexts[n]
			cmd.Printf("%s%-20s %-6s %s\n", marker, n, c.Type, c.Identity)
		}
		return nil
	},
}

var contextUseCmd = &cobra.Command{
	Use:               "use <name>",
	Short:             "Switch the active context",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeContexts,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		if _, ok := cfg.Contexts[args[0]]; !ok {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "context use", Message: "no such context: " + args[0]}
		}
		cfg.Current = args[0]
		if err := cfg.Save(); err != nil {
			return err
		}
		cmd.Printf("Switched to context %q.\n", args[0])
		return nil
	},
}

var contextCurrentCmd = &cobra.Command{
	Use:   "current",
	Short: "Print the active context name",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		if cfg.Current == "" {
			return &clierr.CLIError{Kind: clierr.KindAuth, Command: "context current", Message: "no active context"}
		}
		// stdout, not cmd.Println — scripts pipe $(tvault ctx current) into
		// other commands. Same Cobra-to-stderr footgun fixed for tokens get.
		fmt.Println(cfg.Current)
		return nil
	},
}

var contextRmCmd = &cobra.Command{
	Use:               "rm <name>",
	Aliases:           []string{"delete"},
	Short:             "Remove a stored context",
	Args:              cobra.ExactArgs(1),
	ValidArgsFunction: completeContexts,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load()
		if err != nil {
			return err
		}
		if _, ok := cfg.Contexts[args[0]]; !ok {
			return &clierr.CLIError{Kind: clierr.KindUser, Command: "context rm", Message: "no such context: " + args[0]}
		}
		delete(cfg.Contexts, args[0])
		if cfg.Current == args[0] {
			cfg.Current = ""
		}
		if err := cfg.Save(); err != nil {
			return err
		}
		cmd.Printf("Removed context %q.\n", args[0])
		return nil
	},
}

func init() {
	contextCmd.AddCommand(contextListCmd, contextUseCmd, contextCurrentCmd, contextRmCmd)
	rootCmd.AddCommand(contextCmd)
}
