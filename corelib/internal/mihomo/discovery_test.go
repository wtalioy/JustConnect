package mihomo

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
	"github.com/wtalioy/JustConnect/corelib/internal/testmihomo"
)

func TestControllerCandidatesAndExplicitSelection(t *testing.T) {
	first := testmihomo.Start(t, testmihomo.Options{Transport: "tcp"})
	second := testmihomo.Start(t, testmihomo.Options{Transport: "ipc"})
	processes := []model.Process{ownedProcess(t, first.PID), ownedProcess(t, second.PID)}
	original := Processes
	t.Cleanup(func() { Processes = original })
	Processes = func(context.Context) ([]model.Process, error) { return processes, nil }
	if controller, err := Discover(t.Context(), ""); controller != nil || !errors.Is(err, ErrAmbiguous) {
		if controller != nil {
			controller.Close()
		}
		t.Fatalf("automatic selection must require a choice: %v", err)
	}
	candidates, err := Candidates(t.Context())
	if err != nil || len(candidates) != 2 {
		t.Fatalf("candidate enumeration: %v %v", candidates, err)
	}
	encoded, err := json.Marshal(candidates)
	if err != nil || strings.Contains(string(encoded), first.Secret) || strings.Contains(string(encoded), second.Secret) || strings.Contains(string(encoded), "secret") {
		t.Fatal("candidate presentation exposed controller authentication material")
	}
	for i, candidate := range candidates {
		if candidate.PID != processes[i].PID || candidate.Name == "" {
			t.Fatalf("candidate identity: %+v", candidate)
		}
		controller, err := Discover(t.Context(), candidate.Endpoint)
		if err != nil {
			t.Fatal(err)
		}
		_, err = controller.Query(t.Context(), dns.Question{Name: "selected.example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
		controller.Close()
		if err != nil {
			t.Fatalf("selected controller DNS: %v", err)
		}
	}
	firstCount, _ := first.Counts(t)
	secondCount, _ := second.Counts(t)
	if firstCount != 1 || secondCount != 1 {
		t.Fatalf("selection reached the wrong controller: %d %d", firstCount, secondCount)
	}

	// Native peer ownership still works when no configuration file can be read.
	processes[1].Args = []string{processes[1].Args[0], "-f", filepath.Join(t.TempDir(), "missing.yaml")}
	controller, err := Discover(t.Context(), candidates[1].Endpoint)
	if err != nil {
		t.Fatalf("manual native endpoint with unavailable configuration: %v", err)
	}
	controller.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Candidates(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("candidate cancellation was lost", err)
	}
}

func TestManualControllerRejectsUnownedLoopbackServer(t *testing.T) {
	fixture := testmihomo.Start(t, testmihomo.Options{Transport: "tcp"})
	process := ownedProcess(t, fixture.PID)
	original := Processes
	t.Cleanup(func() { Processes = original })
	Processes = func(context.Context) ([]model.Process, error) { return []model.Process{process}, nil }
	var requests atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(`{"meta":true,"version":"foreign"}`))
	}))
	defer foreign.Close()
	controller, err := Discover(t.Context(), foreign.URL)
	if controller != nil {
		controller.Close()
	}
	if !errors.Is(err, ErrUnavailable) || controller != nil || requests.Load() != 0 {
		t.Fatal("manual address bypassed native listener ownership", err, requests.Load())
	}
	Processes = func(context.Context) ([]model.Process, error) { return nil, nil }
	controller, err = Discover(t.Context(), foreign.URL)
	if err != nil || controller != nil || requests.Load() != 0 {
		t.Fatal("an absent runtime must not contact or trust an unrelated listener", err, requests.Load())
	}
}

func TestControllerAddressTrustBoundary(t *testing.T) {
	for _, value := range []string{"http://192.0.2.1:1234", "http://localhost:1234", "http://127.0.0.1:0", "http://user:password@127.0.0.1:1234", "http://127.0.0.1:1234/configs", "http://127.0.0.1:1234?secret=private", "http://127.0.0.1:1234#private", "http://[::1%25zone]:1234", "unix://relative", "\x00"} {
		if ValidateControllerAddress(value) {
			t.Errorf("unsafe controller address accepted: %q", value)
		}
	}
	for _, value := range []string{"", "http://127.0.0.1:1234", "https://[::1]:4321"} {
		if !ValidateControllerAddress(value) {
			t.Errorf("local controller address rejected: %q", value)
		}
	}
}
