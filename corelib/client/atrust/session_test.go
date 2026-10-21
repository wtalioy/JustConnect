package atrust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client/atrust/auth"
)

func TestSessionRefreshPublishesAndPersists(t *testing.T) {
	c := NewClient(ClientOptions{Session: SessionOptions{SID: "old"}})
	defer c.Close()
	persisted := make(chan []byte, 1)
	retried := make(chan struct{})
	calls := 0
	c.startSessionRefresh(func(ctx context.Context) (auth.LoginResult, error) {
		calls++
		if calls == 1 {
			return auth.LoginResult{SID: "new", Cookies: []auth.Cookie{{Name: "sid", Value: "new"}}}, nil
		}
		close(retried)
		<-ctx.Done()
		return auth.LoginResult{}, ctx.Err()
	}, auth.ClientAuthData{DeviceID: "device", ServerVersionInfo: json.RawMessage(`{"code":0}`)}, func(data []byte) error {
		if sid, err := c.sessionSID(); sid != "new" || err != nil {
			t.Errorf("published SID = %q, %v", sid, err)
		}
		persisted <- data
		return nil
	}, time.Millisecond)
	select {
	case <-retried:
	case <-c.refreshDone:
		t.Fatal("refresh stopped unexpectedly")
	case <-time.After(time.Second):
		t.Fatal("next refresh did not start")
	}
	if calls != 2 {
		t.Fatalf("refresh calls = %d", calls)
	}
	var saved auth.ClientAuthData
	select {
	case data := <-persisted:
		if err := json.Unmarshal(data, &saved); err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cookies not persisted")
	}
	if saved.DeviceID != "device" || len(saved.ServerVersionInfo) == 0 || saved.Cookies[0].Value != "new" {
		t.Fatalf("saved = %+v", saved)
	}
	if sid, err := c.sessionSID(); sid != "new" || err != nil {
		t.Fatalf("retained SID = %q, %v", sid, err)
	}
	if sid, err := (clientInfo{sidProvider: c.sessionSID}).currentSID(); sid != "new" || err != nil {
		t.Fatalf("L3 SID = %q, %v", sid, err)
	}
}

func TestSessionRefreshPreservesSIDOnTransientFailureAndCancels(t *testing.T) {
	c := NewClient(ClientOptions{Session: SessionOptions{SID: "old"}})
	defer c.Close()
	second := make(chan struct{})
	calls := 0
	c.startSessionRefresh(func(ctx context.Context) (auth.LoginResult, error) {
		calls++
		if calls == 1 {
			return auth.LoginResult{}, errors.New("temporary network error")
		}
		close(second)
		<-ctx.Done()
		return auth.LoginResult{}, ctx.Err()
	}, auth.ClientAuthData{}, nil, time.Millisecond)
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("no retry")
	}
	if sid, err := c.sessionSID(); sid != "old" || err != nil {
		t.Fatalf("SID = %q, %v", sid, err)
	}
	done := make(chan struct{})
	go func() { c.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel refresh")
	}
}

func TestExistingL3InfoUsesCurrentSIDAndSignsIt(t *testing.T) {
	c := NewClient(ClientOptions{Session: SessionOptions{SID: "old"}})
	defer c.Close()
	info := clientInfo{sid: "old", sidProvider: c.sessionSID}
	meta := packetMeta{atype: 4, proto: 17, srcIP: net.IPv4(192, 0, 2, 1), dstIP: net.IPv4(198, 51, 100, 2), srcPort: 1234, dstPort: 53}
	for _, sid := range []string{"first", "second"} {
		c.setSessionSID(sid, nil)
		data, err := buildAuthRequest(info, []byte("key"), meta, &conntrack{appID: "app", authID: 1})
		if err != nil {
			t.Fatal(err)
		}
		var req authRequestIP
		if err := json.Unmarshal(data, &req); err != nil {
			t.Fatal(err)
		}
		if req.Sid != sid {
			t.Fatalf("wire SID = %q, want %q", req.Sid, sid)
		}
		signature := req.XRequestSig
		req.XRequestSig = ""
		unsigned, _ := json.Marshal(req)
		if signature != calcXRequestSig([]byte("key"), unsigned) {
			t.Fatal("signature did not cover current SID")
		}
	}
	c.setSessionSID("", auth.ErrSessionInvalid)
	if _, err := buildAuthRequest(info, []byte("key"), meta, &conntrack{}); !errors.Is(err, auth.ErrSessionInvalid) {
		t.Fatalf("auth error = %v", err)
	}
}

func TestConcurrentSessionSIDReaders(t *testing.T) {
	c := NewClient(ClientOptions{})
	defer c.Close()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				c.sessionSID()
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		c.setSessionSID("new", nil)
	}
	wg.Wait()
}

func TestSessionInvalidReturnsToOwner(t *testing.T) {
	for _, code := range []int{10000004, 75500002} {
		payload := []byte(fmt.Sprintf(`{"code":%d,"message":"private gateway detail"}`, code))
		for _, parse := range []func() error{
			func() error { return parseIPAuthResponse(payload) },
			func() error { return parseTCPTunnelAuthResponse(string(payload)) },
		} {
			if err := parse(); !errors.Is(err, auth.ErrSessionInvalid) {
				t.Fatalf("invalid session = %v", err)
			}
		}
		c := NewClient(ClientOptions{})
		conn := &l3TunnelConn{info: clientInfo{onError: c.fail}, closeCh: make(chan struct{})}
		conn.handleAuthResp(authImmediateRetryStatus, payload)
		select {
		case err := <-c.Errors():
			if !errors.Is(err, auth.ErrSessionInvalid) {
				t.Fatalf("L3 failure = %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("L3 error did not reach owner")
		}
		c.Close()
	}
	c := NewClient(ClientOptions{Session: SessionOptions{SID: "old"}})
	c.startSessionRefresh(func(context.Context) (auth.LoginResult, error) {
		return auth.LoginResult{}, auth.ErrSessionInvalid
	}, auth.ClientAuthData{}, nil, time.Millisecond)
	select {
	case err := <-c.Errors():
		if !errors.Is(err, auth.ErrSessionInvalid) {
			t.Fatalf("refresh failure = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("refresh failure did not reach owner")
	}
	c.Close()
	c.Close()
	if _, err := c.sessionSID(); !errors.Is(err, auth.ErrSessionInvalid) {
		t.Fatalf("retained error = %v", err)
	}
}

func TestWorkerPanicIsReturnedAndJoined(t *testing.T) {
	c := NewClient(ClientOptions{})
	c.startWorker(func() { panic("private credentials") })
	select {
	case err := <-c.Errors():
		if err.Error() != "aTrust worker panicked" {
			t.Fatalf("unredacted failure = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("worker panic was not returned")
	}
	c.Close()
}

func TestRefreshObservationsDistinguishTransientFailureAndExpiry(t *testing.T) {
	observations := make(chan [2]string, 16)
	c := NewClient(ClientOptions{Session: SessionOptions{SID: "old"}, Observe: func(stage, result string) { observations <- [2]string{stage, result} }})
	defer c.Close()
	calls := 0
	c.startSessionRefresh(func(context.Context) (auth.LoginResult, error) {
		calls++
		switch calls {
		case 1:
			return auth.LoginResult{}, errors.New("temporary network failure")
		case 2:
			return auth.LoginResult{SID: "new"}, nil
		default:
			return auth.LoginResult{}, auth.ErrSessionInvalid
		}
	}, auth.ClientAuthData{}, nil, time.Millisecond)
	select {
	case err := <-c.Errors():
		if !errors.Is(err, auth.ErrSessionInvalid) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("expiry did not stop session")
	}
	c.Close()
	var results [][2]string
	for len(observations) > 0 {
		results = append(results, <-observations)
	}
	want := [][2]string{{"renewal", "running"}, {"renewal", "failed"}, {"renewal", "running"}, {"renewal", "succeeded"}, {"renewal", "running"}, {"authentication", "required"}}
	if !reflect.DeepEqual(results, want) || calls != 3 {
		t.Fatalf("observations=%v calls=%d", results, calls)
	}
}
