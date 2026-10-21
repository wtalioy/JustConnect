package bridge

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client/atrust"
	"github.com/wtalioy/JustConnect/corelib/client/atrust/auth"
	"github.com/wtalioy/JustConnect/corelib/client/authchallenge"
)

type cacheDialer struct{ net.Dialer }

func (*cacheDialer) ExcludeIP(net.IP) {}

func setupWithCache(t *testing.T, g *gateway, cache []byte) ([]byte, int, int, error) {
	t.Helper()
	host, port, err := net.SplitHostPort(strings.TrimPrefix(g.HTTP.URL, "https://"))
	if err != nil {
		t.Fatal(err)
	}
	portNumber, _ := strconv.Atoi(port)
	client := atrust.NewClient(atrust.ClientOptions{
		Session:        atrust.SessionOptions{Username: "fixture-user"},
		TLSConfig:      g.HTTP.Client().Transport.(*http.Transport).TLSClientConfig,
		UnderlayDialer: &cacheDialer{},
	})
	defer client.Close()
	challenges, invalidations := 0, 0
	var saved []byte
	options := atrust.SetupOptions{
		ServerAddress: host, ServerPort: portNumber, AuthID: "fixture-primary", AuthSubType: "sms",
		LoginMethod: auth.SMSLogin{Phone: "86-123456", Domain: "fixture"}, ClientData: cache,
		SaveClientData:        func(data []byte) error { saved = bytes.Clone(data); return nil },
		ClientDataInvalidated: func() { invalidations++ },
		ChallengeHandler: authchallenge.HandlerFuncs{Code: func(authchallenge.CodeChallenge) (authchallenge.CodeResponse, error) {
			challenges++
			return authchallenge.CodeResponse{Code: "fixture-code"}, nil
		}},
	}
	data, err := client.SetupContext(context.Background(), options)
	if err == nil && !bytes.Equal(data, saved) {
		t.Fatal("saved snapshot differs from the completed setup snapshot")
	}
	return data, challenges, invalidations, err
}

type rejectedNodeDialer struct {
	cacheDialer
	address string
}

func (d *rejectedNodeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if address == d.address {
		return nil, &tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}
	}
	return d.cacheDialer.DialContext(ctx, network, address)
}

func TestAuthenticationSurvivesFailedTunnelSetup(t *testing.T) {
	g := newGateway(t)
	g.resumeCookies.Store(true)
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(g.HTTP.URL, "https://"))
	portNumber, _ := strconv.Atoi(port)
	dialer := &rejectedNodeDialer{address: g.node.Addr().String()}
	var saved []byte
	challenges, invalidations := 0, 0
	attempt := func(cache []byte) error {
		c := atrust.NewClient(atrust.ClientOptions{Session: atrust.SessionOptions{Username: "fixture-user"},
			TLSConfig: g.HTTP.Client().Transport.(*http.Transport).TLSClientConfig, UnderlayDialer: dialer})
		defer c.Close()
		_, err := c.SetupContext(t.Context(), atrust.SetupOptions{ServerAddress: host, ServerPort: portNumber,
			AuthID: "fixture-primary", AuthSubType: "sms", LoginMethod: auth.SMSLogin{Phone: "86-123456", Domain: "fixture"},
			ClientData: cache, SaveClientData: func(data []byte) error { saved = bytes.Clone(data); return nil },
			ClientDataInvalidated: func() { invalidations++ },
			ChallengeHandler: authchallenge.HandlerFuncs{Code: func(authchallenge.CodeChallenge) (authchallenge.CodeResponse, error) {
				challenges++
				return authchallenge.CodeResponse{Code: "fixture-code"}, nil
			}}})
		return err
	}
	var certificate *tls.CertificateVerificationError
	if err := attempt(nil); !errors.As(err, &certificate) || len(saved) == 0 || invalidations != 0 || challenges != 1 {
		t.Fatalf("failed tunnel must preserve verified authentication: saved=%d challenges=%d invalidations=%d err=%v", len(saved), challenges, invalidations, err)
	}
	var original auth.ClientAuthData
	if err := json.Unmarshal(saved, &original); err != nil {
		t.Fatal(err)
	}
	dialer.address = ""
	if err := attempt(saved); err != nil || challenges != 1 || invalidations != 0 || g.authCount.Load() != 1 || g.cacheProbes.Load() != 1 {
		t.Fatalf("retry must restore authentication: challenges=%d invalidations=%d authentications=%d probes=%d err=%v", challenges, invalidations, g.authCount.Load(), g.cacheProbes.Load(), err)
	}
	var restored auth.ClientAuthData
	if err := json.Unmarshal(saved, &restored); err != nil || restored.DeviceID != original.DeviceID || restored.Identity != original.Identity {
		t.Fatal("retry changed the authenticated account or device")
	}
}

func TestClientDataRestoresAfterOrdinaryClose(t *testing.T) {
	g := newGateway(t)
	g.resumeCookies.Store(true)
	first, challenges, invalidated, err := setupWithCache(t, g, nil)
	if err != nil || challenges != 1 || invalidated != 0 {
		t.Fatalf("initial setup: challenges=%d invalidations=%d err=%v", challenges, invalidated, err)
	}
	second, challenges, invalidated, err := setupWithCache(t, g, first)
	if err != nil || challenges != 0 || invalidated != 0 || g.authCount.Load() != 1 || g.cacheProbes.Load() != 1 {
		t.Fatalf("restored setup: challenges=%d invalidations=%d authentications=%d probes=%d err=%v", challenges, invalidated, g.authCount.Load(), g.cacheProbes.Load(), err)
	}
	var a, b auth.ClientAuthData
	if json.Unmarshal(first, &a) != nil || json.Unmarshal(second, &b) != nil || a.DeviceID != b.DeviceID || a.Identity != b.Identity || a.Identity.Username != "fixture-user" || a.Identity.AuthID != "fixture-primary" || a.Identity.AuthSubType != "sms" || a.Identity.AuthType != "auth/smsCheckCode" || a.Identity.LoginDomain != "fixture" || a.Identity.Phone != "86-123456" {
		t.Fatal("restore did not preserve the server-confirmed account and device")
	}
}

func TestAuthenticationCheckpointKeepsResourceCookieRefresh(t *testing.T) {
	g := newGateway(t)
	g.resumeCookies.Store(true)
	g.rotateSID.Store(true)
	encoded, _, _, err := setupWithCache(t, g, nil)
	if err != nil {
		t.Fatal(err)
	}
	var saved auth.ClientAuthData
	if err := json.Unmarshal(encoded, &saved); err != nil || len(saved.Cookies) == 0 {
		t.Fatal("missing authentication snapshot")
	}
	for _, cookie := range saved.Cookies {
		if cookie.Name == "sid" && cookie.Value != "private-resource-sid" {
			t.Fatal("early checkpoint lost the resource response's new session cookie")
		}
	}
	_, challenges, invalidations, err := setupWithCache(t, g, encoded)
	if err != nil || challenges != 0 || invalidations != 0 || g.authCount.Load() != 1 {
		t.Fatalf("refreshed authentication could not resume: challenges=%d invalidations=%d authentications=%d err=%v", challenges, invalidations, g.authCount.Load(), err)
	}
}

func TestClientDataRejectsForeignGatewayBeforeUsingCookies(t *testing.T) {
	first, other := newGateway(t), newGateway(t)
	first.resumeCookies.Store(true)
	other.resumeCookies.Store(true)
	encoded, _, _, err := setupWithCache(t, first, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, challenges, invalidated, err := setupWithCache(t, other, encoded)
	if err != nil || challenges != 1 || invalidated != 1 || other.cacheProbes.Load() != 0 || other.authCount.Load() != 1 {
		t.Fatalf("foreign gateway: challenges=%d invalidations=%d probes=%d authentications=%d err=%v", challenges, invalidated, other.cacheProbes.Load(), other.authCount.Load(), err)
	}
}

func TestClientDataCorruptionFallsBackToOneAuthentication(t *testing.T) {
	g := newGateway(t)
	g.resumeCookies.Store(true)
	_, challenges, invalidated, err := setupWithCache(t, g, []byte(`{"corrupt":`))
	if err != nil || challenges != 1 || invalidated != 1 || g.authCount.Load() != 1 {
		t.Fatalf("corrupt cache: %d %d %v", challenges, invalidated, err)
	}
}

func TestClientDataChecksServerAccountAndExpiration(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(strconv.FormatBool(mismatch), func(t *testing.T) {
			g := newGateway(t)
			g.resumeCookies.Store(true)
			encoded, _, _, err := setupWithCache(t, g, nil)
			if err != nil {
				t.Fatal(err)
			}
			var previous auth.ClientAuthData
			if err := json.Unmarshal(encoded, &previous); err != nil {
				t.Fatal(err)
			}
			if mismatch {
				g.sessions.Store(previous.Cookies[0].Value, "other-user")
			} else {
				g.expireCookies.Store(true)
			}
			fresh, challenges, invalidated, err := setupWithCache(t, g, encoded)
			if err != nil || challenges != 1 || invalidated != 1 || g.authCount.Load() != 2 || g.cacheProbes.Load() != 1 {
				t.Fatalf("server rejection: challenges=%d invalidations=%d authentications=%d probes=%d err=%v", challenges, invalidated, g.authCount.Load(), g.cacheProbes.Load(), err)
			}
			var next auth.ClientAuthData
			if json.Unmarshal(fresh, &next) != nil || next.DeviceID == previous.DeviceID || next.Identity.Username != "fixture-user" {
				t.Fatal("rejected cache retained an old account's device or cookie state")
			}
		})
	}
}

func TestClientDataNetworkFailureDoesNotInvalidate(t *testing.T) {
	g := newGateway(t)
	g.resumeCookies.Store(true)
	encoded, _, _, err := setupWithCache(t, g, nil)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(encoded)
	g.authConfigFails.Store(true)
	_, challenges, invalidated, err := setupWithCache(t, g, encoded)
	if err == nil || challenges != 0 || invalidated != 0 || g.authCount.Load() != 1 || !bytes.Equal(original, encoded) {
		t.Fatalf("network failure destroyed or replayed cache: challenges=%d invalidations=%d authentications=%d err=%v", challenges, invalidated, g.authCount.Load(), err)
	}
}

func TestClientDataInvalidatesWhenTunnelRejectsSession(t *testing.T) {
	g := newGateway(t)
	g.resumeCookies.Store(true)
	encoded, _, _, err := setupWithCache(t, g, nil)
	if err != nil {
		t.Fatal(err)
	}
	g.invalidIP.Store(true)
	_, challenges, invalidated, err := setupWithCache(t, g, encoded)
	if !errors.Is(err, auth.ErrSessionInvalid) || challenges != 0 || invalidated != 1 || g.authCount.Load() != 1 {
		t.Fatalf("tunnel rejection: challenges=%d invalidations=%d authentications=%d err=%v", challenges, invalidated, g.authCount.Load(), err)
	}
}

func TestBridgeAuthenticationCacheEventsRestoreAndInvalidate(t *testing.T) {
	g := newGateway(t)
	g.resumeCookies.Store(true)
	e := New(RunProtocol)
	h := create(t, e)
	c := g.config(t)
	c.Auth.AuthID, c.Auth.SubType = "fixture-primary", "sms"
	c.AuthenticationCache.Enabled = true
	for round := 0; round < 3; round++ {
		if round == 2 {
			g.expireCookies.Store(true)
		}
		if _, status := e.Start(h, configBytes(t, c)); status != OK {
			t.Fatal(status)
		}
		challenges, invalidations, saves := 0, 0, 0
		ready := false
		for !ready {
			ev := next(t, e, h)
			switch ev.Type {
			case "authentication":
				challenges++
				response, _ := json.Marshal(Response{SchemaVersion: ABIVersion, Generation: ev.Generation, RequestID: ev.RequestID, Action: "submit", Code: "fixture-code"})
				if status := e.Respond(h, response); status != OK {
					t.Fatal(status)
				}
			case "authentication_cache":
				if ev.Action == "invalidate" {
					invalidations++
					continue
				}
				if ev.Action != "save" || ev.Cache == nil || ev.Cache.Account != "fixture-user" || len(ev.Cache.Data) == 0 {
					t.Fatal("missing bound cache output")
				}
				saves++
				c.AuthenticationCache.Account = ev.Cache.Account
				c.AuthenticationCache.Data = ev.Cache.Data
			case "state":
				ready = ev.State == "ready"
			case "terminal":
				t.Fatal("cache connection failed", ev.Status)
			}
		}
		expectedChallenges, expectedInvalidations := 1, 0
		if round == 1 {
			expectedChallenges = 0
		}
		if round == 2 {
			expectedInvalidations = 1
		}
		if challenges != expectedChallenges || invalidations != expectedInvalidations || saves != 1 {
			t.Fatalf("round %d: challenges=%d invalidations=%d saves=%d", round, challenges, invalidations, saves)
		}
		if e.Stop(h, 3000) != OK {
			t.Fatal("stop")
		}
		if ev := next(t, e, h); ev.Type != "terminal" || ev.Status != Cancelled {
			t.Fatal("ordinary stop did not finish")
		}
	}
	if g.authCount.Load() != 2 || g.cacheProbes.Load() != 2 {
		t.Fatal("bridge did not restore existing protocol cookies")
	}
}

func TestAuthenticationCacheQueueIsBoundedAndOrdered(t *testing.T) {
	produced := make(chan struct{})
	e := New(func(ctx context.Context, _ Config, host *Session) Status {
		for i := 0; i < 1000; i++ {
			if host.SaveAuthenticationCache("alice", []byte(strconv.Itoa(i))) != OK {
				return Internal
			}
		}
		if host.InvalidateAuthenticationCache() != OK {
			return Internal
		}
		for i := 0; i < 1000; i++ {
			if host.SaveAuthenticationCache("alice", []byte(strconv.Itoa(i))) != OK {
				return Internal
			}
		}
		if host.SaveAuthenticationCache("alice", make([]byte, MaxAuthCache+1)) != Limit {
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
	case <-time.After(3 * time.Second):
		t.Fatal("cache producer blocked on reader")
	}
	if ev := read(t, e, h); ev.State != "starting" {
		t.Fatal("lost starting event")
	}
	if ev := read(t, e, h); ev.Action != "invalidate" {
		t.Fatal("old save survived definitive invalidation")
	}
	if ev := read(t, e, h); ev.Action != "save" || ev.Cache == nil || string(ev.Cache.Data) != "999" {
		t.Fatal("latest save missing after invalidation")
	}
	if _, _, status := e.Read(h, MaxOutput, 0); status != Timeout {
		t.Fatal("unbounded cache notifications")
	}
	if e.Stop(h, 1000) != OK {
		t.Fatal("stop waited for a cache reader")
	}
	if ev := read(t, e, h); ev.Type != "terminal" {
		t.Fatal("lost terminal")
	}
}

func TestBridgeReportsRequiredCredentialsWithoutPostingPassword(t *testing.T) {
	g := newGateway(t)
	g.passwordMethod.Store(true)
	c := g.config(t)
	c.Auth.Method, c.Auth.AuthID, c.Auth.SubType = "auth/psw", "fixture-primary", "password"
	c.Auth.Username = "login-alias"
	e := New(RunProtocol)
	h := create(t, e)
	if _, status := e.Start(h, configBytes(t, c)); status != OK {
		t.Fatal(status)
	}
	if ev := next(t, e, h); ev.State != "starting" {
		t.Fatal("missing starting event")
	}
	if ev := next(t, e, h); ev.Type != "terminal" || ev.Status != CredentialsRequired {
		t.Fatal("missing credentials were not reported safely", ev.Status)
	}
}

func TestBridgeSavesAuthenticationBeforeFailedNodeSetup(t *testing.T) {
	g := newGateway(t)
	g.node.Close()
	c := g.config(t)
	c.AuthenticationCache.Enabled = true
	e := New(RunProtocol)
	h := create(t, e)
	startProtocol(t, e, h, c)
	cached := next(t, e, h)
	if cached.Type != "authentication_cache" || cached.Action != "save" || cached.Cache == nil || cached.Cache.Account != "fixture-user" || len(cached.Cache.Data) == 0 {
		t.Fatalf("authentication was not delivered before transport failure: %+v", cached)
	}
	terminal := next(t, e, h)
	if terminal.Type != "terminal" || terminal.Status != NetworkFailure || g.authCount.Load() != 1 {
		t.Fatalf("event = %+v, authentications = %d", terminal, g.authCount.Load())
	}
}
