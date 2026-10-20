package bridge

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"
	"time"
)

func create(t *testing.T, e *Engine) uint64 {
	t.Helper()
	h, status := e.Create(ABIVersion)
	if status != OK {
		t.Fatal(status)
	}
	t.Cleanup(func() {
		if e.Destroy(h, 1000) != OK {
			t.Error("destroy failed")
		}
	})
	return h
}

func read(t *testing.T, e *Engine, h uint64) event {
	t.Helper()
	data, _, status := e.Read(h, MaxOutput, 1000)
	if status != OK {
		t.Fatalf("read status %d", status)
	}
	var ev event
	if err := json.Unmarshal(data, &ev); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "private-password") || strings.Contains(string(data), "private-response") {
		t.Fatal("secret in event")
	}
	return ev
}

func TestUnavailableLifecycleAndBufferRetry(t *testing.T) {
	e := New(nil)
	if _, s := e.Create(99); s != ABIMismatch {
		t.Fatal(s)
	}
	h := create(t, e)
	g, status := e.Start(h, []byte(configJSON))
	if g != 1 || status != OK {
		t.Fatal(g, status)
	}
	_, n, status := e.Read(h, 0, 1000)
	if status != BufferTooSmall || n == 0 {
		t.Fatal(n, status)
	}
	if _, again, status := e.Read(h, n-1, 0); status != BufferTooSmall || again != n {
		t.Fatal(again, status)
	}
	if _, status := e.Start(h, []byte(configJSON)); status != Busy {
		t.Fatal(status)
	}
	if ev := read(t, e, h); ev.Type != "state" || ev.State != "starting" || ev.Generation != 1 || ev.Sequence != 1 {
		t.Fatal(ev)
	}
	if ev := read(t, e, h); ev.Type != "terminal" || ev.Status != Unsupported || ev.Sequence != 2 {
		t.Fatal(ev)
	}
	if _, _, s := e.Read(h, MaxOutput, 0); s != End {
		t.Fatal(s)
	}
	if e.Stop(h, 1000) != OK || e.Stop(h, 1000) != OK {
		t.Fatal("stop not idempotent")
	}
	if g, s := e.Start(h, []byte(configJSON)); g != 2 || s != OK {
		t.Fatal(g, s)
	}
	read(t, e, h)
	read(t, e, h)
	if e.Destroy(h, 1000) != OK || e.Destroy(h, 1000) != OK {
		t.Fatal("destroy not idempotent")
	}
	if _, _, s := e.Read(h, 0, 0); s != InvalidHandle {
		t.Fatal(s)
	}
	if e.Destroy(h+1000, 0) != InvalidHandle || e.Destroy(0, 0) != InvalidHandle {
		t.Fatal("invented handle accepted")
	}
}

func TestSingleActiveSessionAndInputOwnership(t *testing.T) {
	entered := make(chan Config, 2)
	e := New(func(ctx context.Context, c Config, s *Session) Status {
		entered <- c
		<-ctx.Done()
		return Cancelled
	})
	h1, h2 := create(t, e), create(t, e)
	input := []byte(configJSON)
	if _, s := e.Start(h1, input); s != OK {
		t.Fatal(s)
	}
	for i := range input {
		input[i] = 'x'
	}
	if c := <-entered; c.Auth.Password != "private-password" {
		t.Fatal("input retained")
	}
	if _, s := e.Start(h2, []byte(configJSON)); s != Busy {
		t.Fatal(s)
	}
	if e.Stop(h1, 1000) != OK {
		t.Fatal("stop failed")
	}
	read(t, e, h1)
	read(t, e, h1)
	if _, s := e.Start(h2, []byte(configJSON)); s != OK {
		t.Fatal(s)
	}
	<-entered
}

func TestConcurrentStarts(t *testing.T) {
	e := New(func(ctx context.Context, _ Config, _ *Session) Status { <-ctx.Done(); return Cancelled })
	handles := make([]uint64, MaxHandles)
	for i := range handles {
		handles[i] = create(t, e)
	}
	var wg sync.WaitGroup
	results := make(chan Status, len(handles))
	for _, h := range handles {
		wg.Add(1)
		go func(h uint64) { defer wg.Done(); _, s := e.Start(h, []byte(configJSON)); results <- s }(h)
	}
	wg.Wait()
	close(results)
	count := 0
	for status := range results {
		if status == OK {
			count++
		} else if status != Busy {
			t.Fatal(status)
		}
	}
	if count != 1 {
		t.Fatal("active sessions", count)
	}
	if _, s := e.Create(1); s != Limit {
		t.Fatal(s)
	}
}

func TestBoundedQueuePreservesAuthenticationAndTerminal(t *testing.T) {
	full := make(chan struct{})
	e := New(func(ctx context.Context, _ Config, s *Session) Status {
		if s.Ready() != OK || s.Ready() != Busy {
			return Internal
		}
		for i := 0; i < 10000; i++ {
			s.Diagnostic("keepalive_retry")
		}
		if s.Diagnostic("private-password") != InvalidArgument {
			return Internal
		}
		close(full)
		_, status := s.Authenticate(ctx, Challenge{Kind: "sms"})
		return status
	})
	h := create(t, e)
	e.Start(h, []byte(configJSON))
	<-full
	s := e.lookup(h)
	deadline := time.After(time.Second)
	for {
		s.mu.Lock()
		pending := s.auth != nil
		changed := s.changed
		s.mu.Unlock()
		if pending {
			break
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatal("authentication not queued")
		}
	}
	s.mu.Lock()
	if len(s.queue) > MaxDiagnostics+3 || s.diagnostics != MaxDiagnostics {
		t.Error("unbounded queue", len(s.queue))
	}
	s.mu.Unlock()
	if e.Stop(h, 1000) != OK {
		t.Fatal("stop blocked behind full diagnostics")
	}
	auth, terminal := false, false
	for {
		data, _, status := e.Read(h, MaxOutput, 0)
		if status == End {
			break
		}
		if status != OK {
			t.Fatal(status)
		}
		if strings.Contains(string(data), "private-password") {
			t.Fatal("secret escaped")
		}
		var ev event
		json.Unmarshal(data, &ev)
		auth = auth || ev.Type == "authentication"
		terminal = terminal || ev.Type == "terminal"
	}
	if !auth || !terminal {
		t.Fatal("terminal lost")
	}
}

func TestAuthenticationOwnershipAndStaleResponses(t *testing.T) {
	responseReceived := make(chan Response, 1)
	e := New(func(ctx context.Context, _ Config, s *Session) Status {
		r, status := s.Authenticate(context.Background(), Challenge{Kind: "sms"})
		if status == OK {
			responseReceived <- r
		}
		<-ctx.Done()
		return status
	})
	h := create(t, e)
	e.Start(h, []byte(configJSON))
	read(t, e, h)
	auth := read(t, e, h)
	if auth.Type != "authentication" || auth.RequestID == 0 {
		t.Fatal(auth)
	}
	response := []byte(fmt.Sprintf("{\"schema_version\":1,\"generation\":\"%d\",\"request_id\":\"%d\",\"action\":\"submit\",\"code\":\"private-response\"}", auth.Generation, auth.RequestID))
	for _, wrong := range []string{
		strings.Replace(string(response), "\"generation\":\"1\"", "\"generation\":\"2\"", 1),
		strings.Replace(string(response), fmt.Sprintf("\"request_id\":\"%d\"", auth.RequestID), "\"request_id\":\"999\"", 1),
	} {
		if e.Respond(h, []byte(wrong)) != StaleRequest {
			t.Fatal("stale response accepted")
		}
	}
	if e.Respond(h, response) != OK {
		t.Fatal("response rejected")
	}
	for i := range response {
		response[i] = 'x'
	}
	if r := <-responseReceived; r.Code != "private-response" {
		t.Fatal("response not owned")
	}
	if e.Respond(h, []byte(fmt.Sprintf("{\"schema_version\":1,\"generation\":\"1\",\"request_id\":\"%d\",\"action\":\"cancel\"}", auth.RequestID))) != StaleRequest {
		t.Fatal("duplicate accepted")
	}
	if e.Stop(h, 1000) != OK {
		t.Fatal("stop failed")
	}
	if ev := read(t, e, h); ev.Type != "terminal" || ev.Status != Cancelled {
		t.Fatal(ev)
	}
}

func TestSlowCleanupRetainsBusyAndWakesReaders(t *testing.T) {
	release := make(chan struct{})
	stopping := make(chan struct{})
	e := New(func(ctx context.Context, _ Config, _ *Session) Status {
		<-ctx.Done()
		close(stopping)
		<-release
		return OK
	})
	h, other := create(t, e), create(t, e)
	e.Start(h, []byte(configJSON))
	read(t, e, h)
	reader := make(chan Status, 1)
	go func() { _, _, status := e.Read(h, MaxOutput, 30000); reader <- status }()
	if e.Destroy(h, 0) != Timeout {
		t.Fatal("cleanup should still be pending")
	}
	<-stopping
	select {
	case status := <-reader:
		if status != Cancelled {
			t.Fatal(status)
		}
	case <-time.After(time.Second):
		t.Fatal("reader not woken")
	}
	if _, s := e.Start(other, []byte(configJSON)); s != Busy {
		t.Fatal("active released before cleanup")
	}
	close(release)
	if e.Destroy(h, 1000) != OK {
		t.Fatal("retry destroy failed")
	}
	if _, s := e.Start(h, []byte(configJSON)); s != InvalidHandle {
		t.Fatal(s)
	}
}

func TestIdleStopAndDestroyWakeReaders(t *testing.T) {
	for _, destroy := range []bool{false, true} {
		e := New(nil)
		h := create(t, e)
		result := make(chan Status, 1)
		go func() { _, _, s := e.Read(h, MaxOutput, 30000); result <- s }()
		if destroy {
			e.Destroy(h, 1000)
		} else {
			e.Stop(h, 1000)
		}
		want := End
		if destroy {
			want = InvalidHandle
		}
		select {
		case s := <-result:
			if s != want {
				t.Fatal(s, want)
			}
		case <-time.After(time.Second):
			t.Fatal("blocked idle reader")
		}
	}
}

func TestPanicRedactionAndLimits(t *testing.T) {
	e := New(func(context.Context, Config, *Session) Status { panic("private-password") })
	h := create(t, e)
	e.Start(h, []byte(configJSON))
	read(t, e, h)
	if ev := read(t, e, h); ev.Status != Internal || strings.Contains(ev.Message, "private-password") {
		t.Fatal(ev)
	}
	s := e.lookup(h)
	s.mu.Lock()
	s.generation = math.MaxUint64
	s.mu.Unlock()
	if _, s := e.Start(h, []byte(configJSON)); s != Limit {
		t.Fatal("generation wrapped")
	}
	if _, _, s := e.Read(h, MaxOutput+1, 0); s != InvalidArgument {
		t.Fatal(s)
	}
	if e.Stop(h, MaxWaitMS+1) != InvalidArgument {
		t.Fatal("unbounded timeout")
	}
}

func TestStopPreservesCleanupFailure(t *testing.T) {
	e := New(func(ctx context.Context, _ Config, _ *Session) Status {
		<-ctx.Done()
		return Internal
	})
	h := create(t, e)
	e.Start(h, []byte(configJSON))
	read(t, e, h)
	if e.Stop(h, 1000) != OK {
		t.Fatal("stop failed")
	}
	if ev := read(t, e, h); ev.Status != Internal {
		t.Fatal("cleanup failure hidden", ev)
	}
}

func TestExpiredChallengeCannotAcceptOrAccumulateReplies(t *testing.T) {
	expire, cancel := context.WithCancel(context.Background())
	expired := make(chan Status, 2)
	e := New(func(ctx context.Context, _ Config, s *Session) Status {
		_, status := s.Authenticate(expire, Challenge{Kind: "sms"})
		expired <- status
		// An unread expired request still occupies its reserved queue slot.
		_, status = s.Authenticate(ctx, Challenge{Kind: "sms"})
		expired <- status
		if status != Busy {
			return Internal
		}
		<-ctx.Done()
		return Cancelled
	})
	h := create(t, e)
	e.Start(h, []byte(configJSON))
	read(t, e, h)
	s := e.lookup(h)
	deadline := time.After(time.Second)
	for {
		s.mu.Lock()
		queued := s.auth != nil
		changed := s.changed
		s.mu.Unlock()
		if queued {
			break
		}
		select {
		case <-changed:
		case <-deadline:
			t.Fatal("challenge not queued")
		}
	}
	cancel()
	if status := <-expired; status != Cancelled {
		t.Fatal(status)
	}
	select {
	case status := <-expired:
		if status != Busy {
			t.Fatal(status)
		}
	case <-time.After(time.Second):
		t.Fatal("expired challenges accumulated")
	}
	auth := read(t, e, h)
	response := []byte(fmt.Sprintf("{\"schema_version\":1,\"generation\":\"%d\",\"request_id\":\"%d\",\"action\":\"cancel\"}", auth.Generation, auth.RequestID))
	if status := e.Respond(h, response); status != StaleRequest {
		t.Fatal(status)
	}
}

func TestExpiredResponseDoesNotDependOnWorkerScheduling(t *testing.T) {
	e := New(func(ctx context.Context, _ Config, _ *Session) Status { <-ctx.Done(); return Cancelled })
	h := create(t, e)
	e.Start(h, []byte(configJSON))
	read(t, e, h)
	expired, cancel := context.WithCancel(context.Background())
	cancel()
	s := e.lookup(h)
	s.mu.Lock()
	// Model an expired request whose worker has not yet run its cleanup.
	s.auth = &pending{id: 1, ctx: expired, delivered: true, challenge: Challenge{Kind: "sms"}, response: make(chan Response, 1)}
	s.mu.Unlock()
	response := []byte("{\"schema_version\":1,\"generation\":\"1\",\"request_id\":\"1\",\"action\":\"submit\",\"code\":\"private-response\"}")
	if status := e.Respond(h, response); status != StaleRequest {
		t.Fatal("expired response accepted", status)
	}
}

func TestAuthMethodResultsRespectReservedQueueAndOutputLimits(t *testing.T) {
	for _, methods := range [][]AuthMethod{
		make([]AuthMethod, MaxAuthMethods+1),
		func() []AuthMethod {
			result := make([]AuthMethod, MaxAuthMethods)
			for i := range result {
				result[i] = AuthMethod{Type: "auth/psw", LoginURL: strings.Repeat("a", MaxURL)}
			}
			return result
		}(),
	} {
		e := New(func(_ context.Context, _ Config, s *Session) Status { return s.AuthMethods(methods) })
		h := create(t, e)
		if _, status := e.Start(h, []byte(configJSON)); status != OK {
			t.Fatal(status)
		}
		read(t, e, h)
		if ev := read(t, e, h); ev.Type != "terminal" || ev.Status != Limit || ev.Sequence != 2 {
			t.Fatalf("oversized methods = %+v", ev)
		}
	}
}

func TestAuthenticationDeadlineRejectsLateReplyAndAllowsRetry(t *testing.T) {
	for _, source := range []string{"caller", "core"} {
		t.Run(source, func(t *testing.T) {
			rounds := 0
			e := New(func(ctx context.Context, _ Config, s *Session) Status {
				rounds++
				if rounds == 1 {
					if source == "core" {
						_, status := s.authenticate(ctx, Challenge{Kind: "sms"}, 200*time.Millisecond)
						return status
					}
					deadline, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
					defer cancel()
					_, status := s.Authenticate(deadline, Challenge{Kind: "sms"})
					return status
				}
				_, status := s.Authenticate(ctx, Challenge{Kind: "sms"})
				return status
			})
			h := create(t, e)
			e.Start(h, []byte(configJSON))
			read(t, e, h)
			expired := read(t, e, h)
			terminal := read(t, e, h)
			if terminal.Type != "terminal" || terminal.Status != Timeout {
				t.Fatalf("authentication deadline: %+v", terminal)
			}
			response := func(ev event) []byte {
				return []byte(fmt.Sprintf(`{"schema_version":1,"generation":"%d","request_id":"%d","action":"submit","code":"fixture-code"}`, ev.Generation, ev.RequestID))
			}
			if status := e.Respond(h, response(expired)); status != StaleRequest {
				t.Fatal("late response accepted", status)
			}
			if _, status := e.Start(h, []byte(configJSON)); status != OK {
				t.Fatal("retry failed", status)
			}
			read(t, e, h)
			current := read(t, e, h)
			if status := e.Respond(h, response(expired)); status != StaleRequest {
				t.Fatal("old request entered retry", status)
			}
			if status := e.Respond(h, response(current)); status != OK {
				t.Fatal("new request rejected", status)
			}
			if terminal := read(t, e, h); terminal.Type != "terminal" || terminal.Status != OK {
				t.Fatal(terminal)
			}

		})
	}
}
