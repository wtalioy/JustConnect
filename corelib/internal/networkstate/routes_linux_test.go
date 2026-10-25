package networkstate

import (
	"github.com/wtalioy/JustConnect/corelib/internal/networkstate/model"
	"net/netip"
	"slices"
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

func TestReadIncludesActualIPv4LocalPolicyTable(t *testing.T) {
	snapshot, err := Read()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(snapshot.PolicyRules, func(rule model.PolicyRule) bool {
		return rule.Family == unix.AF_INET && rule.Table == unix.RT_TABLE_LOCAL && rule.Action == 1
	}) {
		t.Fatal("native IPv4 local-table routing rule omitted")
	}
}
