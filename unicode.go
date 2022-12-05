package srp

import (
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// NFKD returns str as a NFKD-normalized
// unicode string, stripped of all leading and trailing
// spaces.
func NFKD(str string) string {
	str = norm.NFKD.String(str)
	str = strings.TrimFunc(str, unicode.IsSpace)
	return str
}
