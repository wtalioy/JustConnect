package mihomo

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/wtalioy/JustConnect/corelib/internal/mihomo/model"
	"github.com/wtalioy/JustConnect/corelib/internal/testmihomo"
)

func TestMain(m *testing.M) {
	if testmihomo.Run() {
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func ownedProcess(t *testing.T, pid int) model.Process {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	list, err := Processes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range list {
		if p.PID == pid {
			return p
		}
	}
	t.Fatal("owned native process was not discoverable")
	return model.Process{}
}

func TestNativeControllerTCPAndIPC(t *testing.T) {
	for _, kind := range []string{"tcp", "ipc"} {
		t.Run(kind, func(t *testing.T) {
			fixture := testmihomo.Start(t, testmihomo.Options{Transport: kind})
			process := ownedProcess(t, fixture.PID)
			client, err := Inspect(t.Context(), process)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
				answer, err := client.Query(t.Context(), dns.Question{Name: "gateway.example.test.", Qtype: qtype, Qclass: dns.ClassINET})
				if err != nil || len(answer.Answer) != 2 || answer.Answer[0].Header().Ttl != 37 || answer.Answer[1].Header().Rrtype != qtype {
					t.Fatalf("native real-DNS CNAME/AAAA response: %v", err)
				}
			}
			var concurrent sync.WaitGroup
			for range 8 {
				concurrent.Go(func() {
					if _, err := client.Query(t.Context(), dns.Question{Name: "parallel.example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}); err != nil {
						t.Errorf("concurrent native controller query: %v", err)
					}
				})
			}
			concurrent.Wait()
			addresses, err := client.Resolver().LookupNetIP(t.Context(), "ip", "gateway.example.test")
			if err != nil || len(addresses) != 2 {
				t.Fatalf("Go resolver did not retain both real address families: %v %v", addresses, err)
			}
		})
	}
}

func TestUnownedPortAndReusedIdentityNeverReceiveCredentials(t *testing.T) {
	first := testmihomo.Start(t, testmihomo.Options{Transport: "tcp"})
	second := testmihomo.Start(t, testmihomo.Options{Transport: "tcp"})
	process := ownedProcess(t, first.PID)
	data, _ := json.Marshal(map[string]any{"external-controller": second.Address, "secret": second.Secret})
	if err := os.WriteFile(first.Configuration, data, 0600); err != nil {
		t.Fatal(err)
	}
	if client, err := Inspect(t.Context(), process); err == nil {
		client.Close()
		t.Fatal("another process acquired controller authority")
	}
	data, _ = json.Marshal(map[string]any{"external-controller": first.Address, "secret": first.Secret})
	if err := os.WriteFile(first.Configuration, data, 0600); err != nil {
		t.Fatal(err)
	}
	process.Started++
	if client, err := Inspect(t.Context(), process); err == nil {
		client.Close()
		t.Fatal("reused process identity acquired controller authority")
	}
	queries, _ := second.Counts(t)
	if queries != 0 {
		t.Fatal("unowned controller received a DNS request")
	}
}

func TestControllerRejectsRedirectOversizeAndMalformedDNS(t *testing.T) {
	var redirected atomic.Int32
	spy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer spy.Close()
	for _, options := range []testmihomo.Options{{Transport: "tcp", Redirect: spy.URL}, {Transport: "tcp", Oversize: true}} {
		fixture := testmihomo.Start(t, options)
		if client, err := Inspect(t.Context(), ownedProcess(t, fixture.PID)); err == nil {
			client.Close()
			t.Fatal("invalid controller response was accepted")
		}
	}
	if redirected.Load() != 0 {
		t.Fatal("controller redirect leaked a credential-bearing request")
	}
	fixture := testmihomo.Start(t, testmihomo.Options{Transport: "tcp"})
	client, err := Inspect(t.Context(), ownedProcess(t, fixture.PID))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	for _, name := range []string{"invalid.example.test.", "nostatus.example.test."} {
		_, err = client.Query(t.Context(), dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET})
		if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), fixture.Secret) {
			t.Fatal("malformed DNS result or sensitive error escaped validation")
		}
	}
}

func TestControllerCancellationAndAmbiguity(t *testing.T) {
	first := testmihomo.Start(t, testmihomo.Options{Transport: "ipc"})
	process := ownedProcess(t, first.PID)
	client, err := Inspect(t.Context(), process)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() {
		_, err := client.Query(ctx, dns.Question{Name: "stall.example.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
		done <- err
	}()
	deadline := time.Now().Add(time.Second)
	for {
		queries, _ := first.Counts(t)
		if queries > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("request did not reach owned controller")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled controller request did not return")
	}
	second := testmihomo.Start(t, testmihomo.Options{Transport: "tcp"})
	other := ownedProcess(t, second.PID)
	original := Processes
	t.Cleanup(func() { Processes = original })
	Processes = func(context.Context) ([]model.Process, error) { return []model.Process{process, other}, nil }
	if c, err := Discover(t.Context()); !errors.Is(err, ErrAmbiguous) {
		if c != nil {
			c.Close()
		}
		t.Fatal("multiple live controllers were silently selected")
	}
}
