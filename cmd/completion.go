package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// completionCmd intentionally replaces Cobra's auto-generated completion command with a hand-rolled one.
var completionCmd = &cobra.Command{
	Use:       "completion [bash|zsh|fish|powershell]",
	Short:     "Generate a shell completion script",
	Args:      cobra.MatchAll(cobra.ExactArgs(1), cobra.OnlyValidArgs),
	ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
	RunE: func(cmd *cobra.Command, args []string) error {
		switch args[0] {
		case "bash":
			return rootCmd.GenBashCompletionV2(os.Stdout, true)
		case "zsh":
			return rootCmd.GenZshCompletion(os.Stdout)
		case "fish":
			return rootCmd.GenFishCompletion(os.Stdout, true)
		case "powershell":
			return rootCmd.GenPowerShellCompletionWithDesc(os.Stdout)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(completionCmd)
}
