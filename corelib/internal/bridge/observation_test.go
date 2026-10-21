package bridge

import (
	"context"
	"testing"
	"time"
)

func TestObservationQueueKeepsLatestPerStageAndTerminal(t *testing.T) {
	produced := make(chan struct{})
	e := New(func(ctx context.Context, _ Config, s *Session) Status {
		for i := 0; i < 1000; i++ {
			if s.Observe("renewal", "failed") != OK {
				return Internal
			}
		}
		if s.Observe("renewal", "succeeded") != OK || s.Observe("traffic", "disabled") != OK || s.Observe("private-url", "succeeded") != InvalidArgument {
			return Internal
		}
		close(produced)
		<-ctx.Done()
		return Cancelled
	})
	h := create(t, e)
	if _, status := e.Start(h, []byte(configJSON)); status != OK {
		t.Fatal(status)
	}
	select {
	case <-produced:
	case <-time.After(time.Second):
		t.Fatal("observation producer blocked")
	}
	if ev := read(t, e, h); ev.State != "starting" {
		t.Fatal(ev)
	}
	ev := read(t, e, h)
	if ev.Type != "observation" || ev.Stage != "renewal" || ev.Result != "succeeded" {
		t.Fatal(ev)
	}
	if _, err := time.Parse(time.RFC3339Nano, ev.ObservedAt); err != nil {
		t.Fatal(err)
	}
	if ev := read(t, e, h); ev.Stage != "traffic" || ev.Result != "disabled" {
		t.Fatal(ev)
	}
	if _, _, status := e.Read(h, MaxOutput, 0); status != Timeout {
		t.Fatal("unbounded observations", status)
	}
	if e.Stop(h, 1000) != OK {
		t.Fatal("stop blocked")
	}
	if ev := read(t, e, h); ev.Type != "terminal" {
		t.Fatal(ev)
	}
	if e.lookup(h).Observe("renewal", "succeeded") != Cancelled {
		t.Fatal("late maintenance accepted")
	}
}
