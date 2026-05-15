// Package output renders command results as table / json / wide / name, and
// resolves the format from flags + TTY detection.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

type Format int

const (
	FormatTable Format = iota
	FormatJSON
	FormatWide
	FormatName
)

// ResolveFormat picks the output format: an explicit flag value wins;
// otherwise TTY → table, non-TTY → json.
func ResolveFormat(flag string, isTTY bool) Format {
	switch strings.ToLower(flag) {
	case "json":
		return FormatJSON
	case "table":
		return FormatTable
	case "wide":
		return FormatWide
	case "name":
		return FormatName
	}
	if isTTY {
		return FormatTable
	}
	return FormatJSON
}

// Render writes rows in the chosen format. columns sets both the order and,
// for table/wide, which keys appear. For name, only columns[0] is printed.
func Render(w io.Writer, format Format, columns []string, rows []map[string]string) error {
	switch format {
	case FormatJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rows)

	case FormatName:
		if len(columns) == 0 {
			return fmt.Errorf("name format needs at least one column")
		}
		for _, r := range rows {
			fmt.Fprintln(w, r[columns[0]])
		}
		return nil

	case FormatTable, FormatWide:
		tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
		header := make([]string, len(columns))
		for i, c := range columns {
			header[i] = strings.ToUpper(c)
		}
		fmt.Fprintln(tw, strings.Join(header, "\t"))
		for _, r := range rows {
			cells := make([]string, len(columns))
			for i, c := range columns {
				cells[i] = r[c]
			}
			fmt.Fprintln(tw, strings.Join(cells, "\t"))
		}
		return tw.Flush()
	}
	return fmt.Errorf("unknown format")
}
