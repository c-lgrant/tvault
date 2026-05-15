package cmd

import (
	"bytes"
	"runtime/debug"
	"strings"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	origVersion, origCommit, origDate := version, commit, date
	t.Cleanup(func() {
		version, commit, date = origVersion, origCommit, origDate
	})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	version = "1.2.3"
	commit = "abc1234"
	date = "2026-05-14"

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetArgs([]string{"version"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("version command errored: %v", err)
	}

	out := buf.String()
	for _, want := range []string{"1.2.3", "abc1234", "2026-05-14"} {
		if !strings.Contains(out, want) {
			t.Errorf("version output missing %q; got: %s", want, out)
		}
	}
}

func TestVersionStringBuildInfoFallback(t *testing.T) {
	origVersion := version
	origRBI := readBuildInfo
	t.Cleanup(func() {
		version = origVersion
		readBuildInfo = origRBI
	})

	version = "dev"
	readBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main: debug.Module{Version: "v0.6.0"},
			Settings: []debug.BuildSetting{
				{Key: "vcs.revision", Value: "deadbeef"},
				{Key: "vcs.time", Value: "2026-05-14T12:00:00Z"},
			},
		}, true
	}

	out := versionString()
	for _, want := range []string{"v0.6.0", "deadbeef", "2026-05-14T12:00:00Z"} {
		if !strings.Contains(out, want) {
			t.Errorf("versionString missing %q; got: %s", want, out)
		}
	}
}

func TestVersionStringBuildInfoUnavailable(t *testing.T) {
	origVersion := version
	origRBI := readBuildInfo
	t.Cleanup(func() {
		version = origVersion
		readBuildInfo = origRBI
	})

	version = "dev"
	readBuildInfo = func() (*debug.BuildInfo, bool) { return nil, false }

	out := versionString()
	for _, want := range []string{"dev", "unknown"} {
		if !strings.Contains(out, want) {
			t.Errorf("versionString missing %q; got: %s", want, out)
		}
	}
}
