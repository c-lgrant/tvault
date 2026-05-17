package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// runShim handles bare `tvault` invocations:
//
//	tvault <service> [more words]  → print that service's credential
//	tvault                          → show help (like any other CLI)
//
// The `tvault <service>` form is the legacy back-compat path that keeps
// `$(tvault <service>)` working in scripts. With no args, fall through to the
// standard help output — listing tokens now lives under `tvault list`.
func runShim(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return cmd.Help()
	}

	cc, err := resolve(cmd, false)
	if err != nil {
		return err
	}

	service := strings.Join(args, " ")
	val, err := cc.Client.GetTokenValue(service)
	if err != nil {
		return enrich(cmd, cc, err)
	}
	// stdout, not cmd.Println (which Cobra writes to OutOrStderr) — scripts
	// rely on $(tvault <svc>) capturing the value.
	fmt.Println(val)
	return nil
}
