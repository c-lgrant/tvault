package cmd

import (
	"strings"

	"github.com/c-lgrant/tvault/internal/api"
	"github.com/spf13/cobra"
)

// parseServiceAndField splits a service argument like "service.subkey" into
// (service, subkey). Splits on the FIRST dot only. If no dot is present,
// returns (service, "").
func parseServiceAndField(arg string) (service, field string) {
	if idx := strings.IndexByte(arg, '.'); idx >= 0 {
		return arg[:idx], arg[idx+1:]
	}
	return arg, ""
}

// resolveTokenOutput handles composite token field/format resolution for both
// the shim and `tk get`. It:
//   - Splits service.subkey syntax (first dot only)
//   - Honors --field flag (wins over dot-sugar if both given)
//   - Applies --json (default) / --kv output formats (only when no subfield)
//   - Returns the final value to print to stdout, or an error
func resolveTokenOutput(cmd *cobra.Command, cc *cmdContext, rawArg string) (string, error) {
	// Parse service.subkey syntax.
	service, subfieldFromDot := parseServiceAndField(rawArg)

	// Check for explicit --field flag (wins over dot-sugar).
	fieldFlag, _ := cmd.Flags().GetString("field")
	subfield := fieldFlag
	if subfield == "" {
		subfield = subfieldFromDot
	}

	// Fetch the raw token value.
	val, err := cc.Client.GetTokenValue(service)
	if err != nil {
		return "", enrich(cmd, cc, err)
	}

	// If a subfield is requested, resolve and return.
	if subfield != "" {
		resolved, err := api.ResolveField(val, subfield)
		if err != nil {
			return "", enrich(cmd, cc, err)
		}
		return resolved, nil
	}

	// No subfield: check output format flags.
	kvMode, _ := cmd.Flags().GetBool("kv")
	if kvMode {
		kv, err := api.ToKV(val)
		if err != nil {
			return "", enrich(cmd, cc, err)
		}
		// ToKV already includes trailing newline per key, so trim to avoid
		// double-newline when fmt.Println adds one.
		return strings.TrimSuffix(kv, "\n"), nil
	}

	// Default: --json (or no flag) → return value as-is.
	return val, nil
}
