package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestExplainKnownCode(t *testing.T) {
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"explain", "VAULT_LOCKED"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("explain errored: %v", err)
	}
	if !strings.Contains(buf.String(), "locked") {
		t.Errorf("explain VAULT_LOCKED output = %s", buf.String())
	}
}

func TestExplainUnknownCode(t *testing.T) {
	rootCmd.SetArgs([]string{"explain", "NOPE_NOT_REAL"})
	err := rootCmd.Execute()
	if err == nil {
		t.Error("explain of an unknown code should error")
	}
}
