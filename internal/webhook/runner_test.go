package webhook

import "testing"

// ExecRunner must satisfy ComposeRunner — this is a compile-time check that
// fails the build if the interface and implementation drift apart.
func TestExecRunnerSatisfiesInterface(t *testing.T) {
	var _ ComposeRunner = ExecRunner{}
}
