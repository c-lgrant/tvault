package api

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/c-lgrant/tvault/internal/clierr"
)

// ResolveField parses a composite token value (JSON object) and extracts the
// specified field. Returns the field value as a bare string (unquoted for JSON
// strings, compact JSON for non-string values).
//
// Exit codes:
//   - KindUser (1): value is not a JSON object
//   - KindEmpty (6): value is a JSON object but the requested key is absent
func ResolveField(value, key string) (string, error) {
	var obj map[string]any
	if err := json.Unmarshal([]byte(value), &obj); err != nil {
		return "", &clierr.CLIError{
			Kind:    clierr.KindUser,
			Message: "not a composite token (value is not a JSON object)",
		}
	}

	val, ok := obj[key]
	if !ok {
		return "", &clierr.CLIError{
			Kind:    clierr.KindEmpty,
			Message: fmt.Sprintf("composite token has no field %q", key),
		}
	}

	// For string values, return the unquoted string.
	if s, ok := val.(string); ok {
		return s, nil
	}

	// For non-string JSON values (number/bool/object/array), return compact JSON.
	raw, err := json.Marshal(val)
	if err != nil {
		return "", &clierr.CLIError{
			Kind:    clierr.KindServer,
			Message: fmt.Sprintf("failed to serialize field %q: %v", key, err),
		}
	}
	return string(raw), nil
}

// ToKV parses a composite token value (JSON object) and returns sorted
// KEY=VALUE lines (one per line, keys sorted ascending).
//
// Exit codes:
//   - KindUser (1): value is not a JSON object
func ToKV(value string) (string, error) {
	var obj map[string]any
	if err := json.Unmarshal([]byte(value), &obj); err != nil {
		return "", &clierr.CLIError{
			Kind:    clierr.KindUser,
			Message: "not a composite token (value is not a JSON object)",
		}
	}

	// Sort keys ascending.
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var result string
	for _, k := range keys {
		v := obj[k]
		// For string values, use the unquoted string.
		if s, ok := v.(string); ok {
			result += fmt.Sprintf("%s=%s\n", k, s)
			continue
		}
		// For non-string JSON values, use compact JSON.
		raw, err := json.Marshal(v)
		if err != nil {
			return "", &clierr.CLIError{
				Kind:    clierr.KindServer,
				Message: fmt.Sprintf("failed to serialize field %q: %v", k, err),
			}
		}
		result += fmt.Sprintf("%s=%s\n", k, string(raw))
	}
	return result, nil
}
