package cmd

import (
	"os"
	"testing"
)

// TestMain clears the variables that change which context a command uses, so
// the tests give the same result in a shell that is pinned to a context.
func TestMain(m *testing.M) {
	os.Unsetenv(contextEnv)
	os.Exit(m.Run())
}
