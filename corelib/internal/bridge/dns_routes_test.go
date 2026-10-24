package bridge

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"
)

func dnsRouteSession(t *testing.T) (*Engine, uint64, *Session, uint64) {
	t.Helper()
	e := New(func(ctx context.Context, _ Config, s *Session) Status {
		s.Ready()
		<-ctx.Done()
		return Cancelled
	})
	h := create(t, e)
	generation, status := e.Start(h, []byte(`{"schema_version":1,"server":{"host":"vpn.example.invalid","port":443}}`))
	if status != OK {
		t.Fatal(status)
	}
	read(t, e, h)
	if ready := read(t, e, h); ready.State != "ready" {
		t.Fatal(ready)
	}
	return e, h, e.lookup(h), generation
}

func TestDNSRoutesRequireDeliveredGenerationBoundAcknowledgement(t *testing.T) {
	for _, applied := range []bool{true, false} {
		t.Run(map[bool]string{true: "success", false: "failure"}[applied], func(t *testing.T) {
			e, h, s, generation := dnsRouteSession(t)
			done := make(chan Status, 1)
			go func() {
				done <- s.publishDNSRoutes(t.Context(), generation, []netip.Addr{netip.MustParseAddr("203.0.113.7")}, time.Second)
			}()
			// A size probe does not deliver the request or authorize an acknowledgement.
			if _, _, status := e.Read(h, 0, 1000); status != BufferTooSmall {
				t.Fatal(status)
			}
			s.mu.Lock()
			request := s.dnsRoutes.id
			s.mu.Unlock()
			if status := e.AcknowledgeDNSRoutes(h, generation, request, true); status != StaleRequest {
				t.Fatal(status)
			}
			event := read(t, e, h)
			if event.Type != "dns_routes" || len(event.Addresses) != 1 || event.Addresses[0] != "203.0.113.7" {
				t.Fatal(event)
			}
			select {
			case result := <-done:
				t.Fatal("DNS escaped without publication", result)
			default:
			}
			for _, value := range [][2]uint64{{generation + 1, request}, {generation, request + 1}} {
				if status := e.AcknowledgeDNSRoutes(h, value[0], value[1], true); status != StaleRequest {
					t.Fatal(status)
				}
			}
			if status := e.AcknowledgeDNSRoutes(h, generation, request, applied); status != OK {
				t.Fatal(status)
			}
			want := NetworkFailure
			if applied {
				want = OK
			}
			if result := <-done; result != want {
				t.Fatal(result, want)
			}
			if status := e.AcknowledgeDNSRoutes(h, generation, request, applied); status != StaleRequest {
				t.Fatal("duplicate result", status)
			}
		})
	}
}

func TestDNSRoutesTimeoutAndCancellationKeepQueueBounded(t *testing.T) {
	e, h, s, generation := dnsRouteSession(t)
	addresses := []netip.Addr{netip.MustParseAddr("203.0.113.7")}
	if status := s.publishDNSRoutes(t.Context(), generation, addresses, time.Millisecond); status != Timeout {
		t.Fatal(status)
	}
	s.mu.Lock()
	remaining := len(s.queue)
	s.mu.Unlock()
	if remaining != 0 {
		t.Fatal("expired unread publication retained an event", remaining)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	var workers sync.WaitGroup
	results := make(chan Status, 64)
	for index := 0; index < cap(results); index++ {
		workers.Add(1)
		go func() { defer workers.Done(); results <- s.publishDNSRoutes(ctx, generation, addresses, time.Minute) }()
	}
	if _, _, status := e.Read(h, 0, 1000); status != BufferTooSmall {
		t.Fatal(status)
	}
	s.mu.Lock()
	queued := len(s.queue)
	s.mu.Unlock()
	if queued != 1 {
		t.Fatal("unbounded concurrent publication queue", queued)
	}
	cancel()
	joined := make(chan struct{})
	go func() { workers.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("publication cancellation did not join queued callers")
	}
	close(results)
	for status := range results {
		if status != Cancelled {
			t.Fatal(status)
		}
	}
	s.mu.Lock()
	remaining = len(s.queue)
	s.mu.Unlock()
	if remaining != 0 {
		t.Fatal("cancelled publications retained events", remaining)
	}
	// Session cancellation also releases callers waiting for the one publication slot.
	for index := 0; index < cap(results); index++ {
		workers.Add(1)
		go func() { defer workers.Done(); _ = s.publishDNSRoutes(t.Context(), generation, addresses, time.Minute) }()
	}
	if _, _, status := e.Read(h, 0, 1000); status != BufferTooSmall {
		t.Fatal(status)
	}
	if e.Stop(h, 1000) != OK {
		t.Fatal("stop failed")
	}
	joined = make(chan struct{})
	go func() { workers.Wait(); close(joined) }()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("stop did not release publication slot waiters")
	}
	if status := s.publishDNSRoutes(t.Context(), generation, addresses, time.Second); status != Cancelled {
		t.Fatal("stopped generation published routes", status)
	}
}
