package bridge

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/policy"
)

func policyInput(generation, revision uint64, protected, campus []string) []byte {
	data, _ := json.Marshal(PolicyUpdate{ABIVersion, generation, revision, protected, campus})
	return data
}

func TestPolicyUpdatesValidateBeforeReplacingAndRejectOldIdentities(t *testing.T) {
	entered := make(chan *Session, 2)
	initial := make(chan *policy.ProtectionPolicy, 2)
	e := New(func(ctx context.Context, _ Config, s *Session) Status {
		initial <- s.ProtectionPolicy()
		entered <- s
		<-ctx.Done()
		return Cancelled
	})
	h := create(t, e)
	inputConfig := strings.Replace(configJSON, `"schema_version":1`, `"schema_version":1,"protection":{"protected":["192.168.50.0/24"],"campus":[]}`, 1)
	initialInput := []byte(inputConfig)
	g, status := e.Start(h, initialInput)
	clear(initialInput)
	if status != OK {
		t.Fatal(status)
	}
	s := <-entered
	first := <-initial
	if first == nil {
		t.Fatal("runner entered before initial protection")
	}
	if allowed, prefix := first.CampusAllowed(netip.MustParseAddr("192.168.50.17")); allowed || !prefix.IsValid() {
		t.Fatal("initial original-network protection not enforced")
	}
	input := policyInput(g, 2, []string{"192.168.50.0/24"}, []string{"192.168.50.17"})
	if applied, status := e.UpdatePolicy(h, input); applied != g || status != OK {
		t.Fatal(applied, status)
	}
	clear(input)
	snapshot := s.ProtectionPolicy()
	if allowed, _ := snapshot.CampusAllowed(netip.MustParseAddr("192.168.50.17")); !allowed {
		t.Fatal("choice not applied")
	}
	for _, input := range [][]byte{
		[]byte(`{"schema_version":2,"generation":"1","revision":"3","protected":[],"campus":[]}`),
		[]byte(`{"schema_version":1,"generation":"1","revision":3,"protected":[],"campus":[]}`),
		[]byte(`{"schema_version":1,"generation":"1","revision":"3","protected":[],"campus":[],"command":"untrusted"}`),
		policyInput(g, 3, []string{"192.168.50.1/24"}, []string{}),
		policyInput(g, 3, nil, []string{}),
		policyInput(g, 3, []string{}, nil),
		[]byte(`{"schema_version":1,"generation":"1","revision":"3","protected":[],"campus":[],"revision":"4"}`),
	} {
		if applied, status := e.UpdatePolicy(h, input); applied != 0 || status != InvalidArgument {
			t.Fatal(applied, status)
		}
	}
	for _, input := range [][]byte{
		policyInput(g, 1, []string{}, []string{}),
		policyInput(g, 2, []string{}, []string{}),
		policyInput(g+1, 3, []string{}, []string{}),
	} {
		if applied, status := e.UpdatePolicy(h, input); applied != 0 || status != StaleRequest {
			t.Fatal(applied, status)
		}
	}
	if s.ProtectionPolicy() != snapshot {
		t.Fatal("failed update replaced a valid snapshot")
	}
	if _, status := e.UpdatePolicy(h, policyInput(g, 3, []string{"192.168.50.0/24"}, []string{})); status != OK {
		t.Fatal(status)
	}
	if allowed, _ := s.ProtectionPolicy().CampusAllowed(netip.MustParseAddr("192.168.50.17")); allowed {
		t.Fatal("removal did not restore protection")
	}
	if allowed, _ := snapshot.CampusAllowed(netip.MustParseAddr("192.168.50.17")); !allowed {
		t.Fatal("reader snapshot mutated")
	}
	if e.Stop(h, 1000) != OK {
		t.Fatal("stop")
	}
	read(t, e, h)
	read(t, e, h)
	g2, status := e.Start(h, []byte(configJSON))
	if status != OK {
		t.Fatal(status)
	}
	<-entered
	if s.ProtectionPolicy() != nil || <-initial != nil {
		t.Fatal("old policy leaked into a new session")
	}
	if _, status := e.UpdatePolicy(h, policyInput(g, 4, []string{}, []string{})); status != StaleRequest {
		t.Fatal(status)
	}
	if applied, status := e.UpdatePolicy(h, policyInput(g2, 1, []string{}, []string{})); applied != g2 || status != OK {
		t.Fatal(applied, status)
	}
}

func TestPolicyUpdateCannotCommitAfterStopOrAffectAuthMethodQueries(t *testing.T) {
	entered, release := make(chan *Session, 1), make(chan struct{})
	e := New(func(ctx context.Context, _ Config, s *Session) Status {
		entered <- s
		<-ctx.Done()
		<-release
		return Cancelled
	})
	h := create(t, e)
	g, status := e.Start(h, []byte(configJSON))
	if status != OK {
		t.Fatal(status)
	}
	s := <-entered
	var wg sync.WaitGroup
	for i := uint64(1); i <= 64; i++ {
		wg.Add(1)
		go func(revision uint64) {
			defer wg.Done()
			_, status := e.UpdatePolicy(h, policyInput(g, revision, []string{"192.168.50.0/24"}, []string{}))
			if status != OK && status != StaleRequest {
				t.Error(status)
			}
			_ = s.ProtectionPolicy()
		}(i)
	}
	if e.Stop(h, 0) != Timeout {
		t.Fatal("runner should retain its owner until cleanup")
	}
	before := s.ProtectionPolicy()
	wg.Wait()
	if s.ProtectionPolicy() != before {
		t.Fatal("update committed after stop")
	}
	if applied, status := e.UpdatePolicy(h, policyInput(g, 100, []string{}, []string{})); applied != 0 || status != StaleRequest {
		t.Fatal(applied, status)
	}
	close(release)
	if e.Stop(h, 1000) != OK {
		t.Fatal("cleanup")
	}
	read(t, e, h)
	read(t, e, h)
	query := strings.Replace(configJSON, `"schema_version":1`, `"schema_version":1,"operation":"auth_methods"`, 1)
	g, status = e.Start(h, []byte(query))
	if status != OK {
		t.Fatal(status)
	}
	<-entered
	if applied, status := e.UpdatePolicy(h, policyInput(g, 1, []string{}, []string{})); applied != 0 || status != Unsupported {
		t.Fatal(applied, status)
	}
}
