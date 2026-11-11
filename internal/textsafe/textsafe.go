// Package textsafe makes server-supplied text safe to print in a terminal.
package textsafe

import (
	"strconv"
	"strings"
	"unicode"
)

// Safe returns s unchanged when it is plain printable text. Anything with
// control, escape or invisible formatting characters (ANSI sequences,
// newlines, bidi overrides) is returned quoted with those characters escaped,
// so a name can't repaint or spoof what the user is reading or confirming.
func Safe(s string) string {
	if strings.IndexFunc(s, func(r rune) bool { return r != ' ' && !unicode.IsPrint(r) }) >= 0 {
		return strconv.Quote(s)
	}
	return s
}
