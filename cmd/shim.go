package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// runShim handles bare `tvault` invocations:
//
//	tvault <service> [more words]  → print that service's credential
//	tvault service.field           → extract field from composite token
//	tvault --field key <service>   → extract field (explicit form)
//	tvault --kv <service>          → print composite as KEY=VALUE lines
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

	// For multi-arg shim calls (e.g., "tvault some service"), join them.
	// Each arg is independently resolved if --field/--kv are set.
	service := strings.Join(args, " ")

	val, err := resolveTokenOutput(cmd, cc, service)
	if err != nil {
		return err
	}
	// stdout, not cmd.Println (which Cobra writes to OutOrStderr) — scripts
	// rely on $(tvault <svc>) capturing the value.
	fmt.Println(val)
	return nil
}
