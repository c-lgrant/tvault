package cmd

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// readBuildInfo is swappable in tests so the BuildInfo-fallback path can be
// exercised without an actual go-install build.
var readBuildInfo = debug.ReadBuildInfo

// versionString returns the formatted version line. When goreleaser has injected
// ldflags (the binary distribution path), version != "dev" and we use them
// directly. Otherwise — typically a `go install` build — we read the module
// version and VCS metadata via debug.ReadBuildInfo so users still see something
// meaningful instead of "dev / none / unknown".
func versionString() string {
	if version != "dev" {
		return fmt.Sprintf("tvault %s (commit %s, built %s)", version, commit, date)
	}
	info, ok := readBuildInfo()
	if !ok {
		return "tvault dev (commit unknown, built unknown)"
	}
	v := info.Main.Version
	if v == "" || v == "(devel)" {
		v = "dev"
	}
	var rev, when string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.time":
			when = s.Value
		}
	}
	if rev == "" {
		rev = "unknown"
	}
	if when == "" {
		when = "unknown"
	}
	return fmt.Sprintf("tvault %s (commit %s, built %s)", v, rev, when)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the tvault version, commit, and build date",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Println(versionString())
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
