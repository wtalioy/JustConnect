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
		if row.Source != "" {
			address, err := netip.ParseAddr(row.Source)
			if err != nil || address.String() != row.Source {
				t.Fatalf("preferred source is not an address: %+v", row)
			}
		}
		prefix := netip.MustParsePrefix(row.Destination)
		if row.Table == unix.RT_TABLE_LOCAL && row.Kind == unix.RTN_LOCAL && prefix.Contains(netip.MustParseAddr("127.0.0.1")) {
			if row.Scope != unix.RT_SCOPE_HOST {
				t.Fatalf("local route lost its native scope: %+v", row)
			}
			return
		}
	}
	t.Fatal("native local table omitted; policy tables must not be filtered to main")
}
