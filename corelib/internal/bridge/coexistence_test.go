package bridge

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/wtalioy/JustConnect/corelib"
)

func TestCoexistenceRejectsUntrustedStateAndStaleGeneration(t *testing.T) {
	e := New(nil)
	h, status := e.Create(ABIVersion)
	if status != OK {
		t.Fatal(status)
	}
	s := e.lookup(h)
	s.running, s.connectOperation, s.generation, s.ctx = true, true, 7, context.Background()
	s.protocol = corelib.NewSession(corelib.Options{})
	input := func(generation string, endpoints any) []byte {
		data, _ := json.Marshal(map[string]any{"schema_version": ABIVersion, "generation": generation, "system_proxy_endpoints": endpoints, "system_proxy_managed": false})
		return data
	}
	for _, endpoints := range []any{nil, "127.0.0.1:7897", []string{""}, []string{"example.test:7897"}, []string{"192.0.2.1:7897"},
		[]string{"127.0.0.1:0"}, []string{"127.0.0.1:07897"}, []string{"127.0.0.1:7897", "127.0.0.1:7897"}, []string{"127.0.0.1:7897/private"}} {
		if applied, status := e.UpdateCoexistence(h, input("7", endpoints)); status != InvalidArgument || applied != 0 {
			t.Fatal("untrusted endpoint acquired routing authority", endpoints, status)
		}
	}
	if _, status := e.UpdateCoexistence(h, input("6", []string{})); status != StaleRequest {
		t.Fatal(status)
	}
	if _, status := e.UpdateCoexistence(h, input("7", []string{})); status != Busy {
		t.Fatal("unready session accepted routing change", status)
	}
	s.ready = true
	if _, status := e.UpdateCoexistence(h, input("7", []string{})); status != Busy {
		t.Fatal("detached protocol accepted routing change", status)
	}
	if _, status := e.Coexistence(h, 7); status != Busy {
		t.Fatal("unacknowledged state was exposed", status)
	}
	s.protocol = nil
	if _, status := e.UpdateCoexistence(h, input("7", []string{})); status != Unsupported {
		t.Fatal("non-protocol driver accepted coexistence", status)
	}
	s.stopping = true
	if _, status := e.UpdateCoexistence(h, input("7", []string{})); status != StaleRequest {
		t.Fatal(status)
	}
	if _, status := e.Coexistence(h, 7); status != StaleRequest {
		t.Fatal(status)
	}
}
