package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/client/authchallenge"
)

func TestRadiusChallengeEndpoint(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/passport/v1/auth/challenge" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		fmt.Fprint(w, `{"code":0,"data":{"nextService":"auth/enhancedDone"}}`)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	session.username = "user"
	step, err := session.submitTokenAt("auth/challenge", map[string]interface{}{
		"username": "user", "radiusToken": "123456", "skipSecondaryAuth": 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Service != "auth/enhancedDone" {
		t.Fatalf("unexpected next step: %+v", step)
	}
}

func TestEnhancedAndBindAuthDeviceEndpoints(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch requests {
		case 1:
			if r.Method != http.MethodGet || r.URL.Path != "/passport/v1/auth/preEnhancedAuth" {
				t.Errorf("unexpected enhanced request: %s %s", r.Method, r.URL.Path)
			}
			if r.URL.Query().Get("authId") != "pre-id" {
				t.Errorf("missing enhanced authId: %s", r.URL.RawQuery)
			}
			fmt.Fprint(w, `{"code":0,"data":{"nextService":"auth/bindAuthDevice","nextServiceList":[{"authId":"bind-id","authType":"auth/bindAuthDevice"}]}}`)
		case 2:
			if r.Method != http.MethodPost || r.URL.Path != "/passport/v1/auth/bindAuthDevice" {
				t.Errorf("unexpected bind request: %s %s", r.Method, r.URL.Path)
			}
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Error(err)
			}
			if payload["deviceId"] != "device-id" || payload["authId"] != "bind-id" {
				t.Errorf("unexpected bind payload: %+v", payload)
			}
			fmt.Fprint(w, `{"code":0,"data":{"nextService":"auth/enhancedConfirm"}}`)
		default:
			t.Errorf("unexpected extra request")
		}
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	session.deviceID = "device-id"
	session.challengeHandler = authchallenge.HandlerFuncs{TrustedDevice: func() (bool, error) { return true, nil }}
	step, err := session.completeEnhancedAuth(authStep{Service: "auth/preEnhancedAuth", AuthID: "pre-id"})
	if err != nil {
		t.Fatal(err)
	}
	step, err = session.bindAuthDevice(step)
	if err != nil {
		t.Fatal(err)
	}
	if step.Service != "auth/enhancedConfirm" {
		t.Fatalf("unexpected next step: %+v", step)
	}
}

func TestBindAuthDeviceRequiresExplicitConfirmation(t *testing.T) {
	for _, decision := range []string{"missing", "unsupported", "decline", "error", "cancelled-before", "cancelled-during"} {
		t.Run(decision, func(t *testing.T) {
			requests := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; fmt.Fprint(w, `{"code":0,"data":{}}`) }))
			defer server.Close()
			session := newTLSTestSession(server)
			defer session.Close()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			session.SetContext(ctx)
			expected := context.Canceled
			calls := 0
			switch decision {
			case "missing":
				expected = authchallenge.ErrUnsupported
			case "unsupported":
				session.challengeHandler = authchallenge.HandlerFuncs{}
				expected = authchallenge.ErrUnsupported
			default:
				session.challengeHandler = authchallenge.HandlerFuncs{TrustedDevice: func() (bool, error) {
					calls++
					switch decision {
					case "error":
						return false, context.Canceled
					case "cancelled-during":
						cancel()
						return true, nil
					}
					return false, nil
				}}
			}
			if decision == "cancelled-before" {
				cancel()
			}
			if _, err := session.bindAuthDevice(authStep{Service: "auth/bindAuthDevice"}); !errors.Is(err, expected) {
				t.Fatalf("wrong error: %v", err)
			}
			if requests != 0 {
				t.Fatal("bound a device without a current explicit confirmation")
			}
			if decision == "cancelled-before" && calls != 0 {
				t.Fatal("asked for a cancelled session")
			}
		})
	}
}

func TestUnsupportedAuthenticationStepIsTyped(t *testing.T) {
	for _, service := range []string{"auth/token", "auth/futureStep?private-value"} {
		session := NewSession("unused.invalid", nil)
		defer session.Close()
		if err := session.continueAuth(authStep{Service: service}); !errors.Is(err, authchallenge.ErrUnsupported) {
			t.Fatalf("service %q: %v", service, err)
		}
	}
}
