package networkstate

import (
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadRetainsLocalTableAndDoesNotOnlyReportMainTable(t *testing.T) {
	snapshot, err := Read()
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range snapshot.Routes {
		prefix := netip.MustParsePrefix(row.Destination)
		if row.Table == unix.RT_TABLE_LOCAL && prefix.Contains(netip.MustParseAddr("127.0.0.1")) {
			return
		}
	}
	t.Fatal("native local table omitted; policy tables must not be filtered to main")
}
