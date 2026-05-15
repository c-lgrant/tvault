package cmd

import "github.com/spf13/cobra"

var vaultCmd = &cobra.Command{
	Use:   "vault",
	Short: "Lock, unlock, or inspect the vault (admin only)",
}

var vaultLockCmd = &cobra.Command{
	Use:   "lock",
	Short: "Lock the vault — blocks all mutating operations",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolve(cmd, true)
		if err != nil {
			return err
		}
		if err := cc.Client.VaultLock(); err != nil {
			return enrich(cmd, cc, err)
		}
		cmd.PrintErrln("Vault locked. Mutating operations are now blocked.")
		return nil
	},
}

var vaultUnlockCmd = &cobra.Command{
	Use:   "unlock",
	Short: "Unlock the vault",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolve(cmd, true)
		if err != nil {
			return err
		}
		if err := cc.Client.VaultUnlock(); err != nil {
			return enrich(cmd, cc, err)
		}
		cmd.PrintErrln("Vault unlocked.")
		return nil
	},
}

var vaultStatusCmd = &cobra.Command{
	Use:     "status",
	Aliases: []string{"stat"},
	Short:   "Show whether the vault is locked",
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		cc, err := resolve(cmd, true)
		if err != nil {
			return err
		}
		st, err := cc.Client.VaultStatus()
		if err != nil {
			return enrich(cmd, cc, err)
		}
		state := "unlocked"
		if st.IsLocked {
			state = "locked"
		}
		cmd.Printf("vault: %s (mode: %s)\n", state, st.VaultMode)
		return nil
	},
}

func init() {
	vaultCmd.AddCommand(vaultLockCmd, vaultUnlockCmd, vaultStatusCmd)
	rootCmd.AddCommand(vaultCmd)
}
