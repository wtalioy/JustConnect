package mihomo

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/internal/testmihomo"
)

func TestNativeControllerRejectsIncompleteRuntimeState(t *testing.T) {
	const base = `{"mode":"rule","socks-port":0,"mixed-port":0,"interface-name":"","tun":{"enable":false}}`
	for _, test := range []struct{ name, body string }{
		{"missing mode", strings.Replace(base, `"mode":"rule",`, "", 1)},
		{"unknown mode", strings.Replace(base, `"rule"`, `"unknown"`, 1)},
		{"missing switch", strings.Replace(base, `"enable":false`, `"device":"unconfirmed"`, 1)},
		{"invalid port", strings.Replace(base, `"socks-port":0`, `"socks-port":65536`, 1)},
		{"invalid exclusion", strings.Replace(base, `"enable":false`, `"enable":false,"route-exclude-address":[null]`, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := testmihomo.Start(t, testmihomo.Options{Transport: "ipc", RuntimeResponse: json.RawMessage(test.body)})
			if c, err := Inspect(t.Context(), ownedProcess(t, fixture.PID)); !errors.Is(err, ErrUnavailable) {
				if c != nil {
					c.Close()
				}
				t.Fatal("unconfirmed runtime facts acquired controller authority", err)
			}
		})
	}
}
