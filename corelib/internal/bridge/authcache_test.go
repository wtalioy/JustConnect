package bridge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"

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
