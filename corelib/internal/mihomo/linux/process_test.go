//go:build linux

package linux

import (
	"strings"
	"testing"
)

func TestParseProcStatReadsNameAndStartTime(t *testing.T) {
	header := "987 (custom (proxy)\nname) S" + strings.Repeat(" 0", 18)
	name, started, err := parseProcStat([]byte(header + " 123456789 42\n"))
	if err != nil || string(name) != "custom (proxy)\nname" || started != 123456789 {
		t.Fatalf("parseProcStat() = %q, %d, %v", name, started, err)
	}
	for _, malformed := range []string{
		"987 (missing terminator",
		header,
		header + " invalid 42",
	} {
		if _, _, err := parseProcStat([]byte(malformed)); err == nil {
			t.Fatalf("accepted malformed stat %q", malformed)
		}
	}
}
