package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/client/authchallenge"
)

func TestPublicFudanMethodMetadata(t *testing.T) {
	data, err := os.ReadFile("testdata/fudan-auth-config.json")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/passport/v1/public/authConfig" {
			t.Errorf("unexpected request path: %s", r.URL.Path)
		}
		w.Write(data)
	}))
	defer server.Close()
	session := newTLSTestSession(server)
	defer session.Close()
	methods, err := session.GetAuthInfoList()
	if err != nil || len(methods) != 1 {
		t.Fatalf("query: %v, %d methods", err, len(methods))
	}
	m := methods[0]
	if m.AuthID != "29531010-5b0c-11f0-91ce-774b05826354" || m.SubType != "https" || m.LoginDomain != "id.fudan.edu.cn" || m.AuthType != "auth/httpsOauth2" {
		t.Fatalf("public authentication identity not preserved: %+v", m)
	}
}

func TestLoginUsesExactReturnedIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, id, subtype string
		duplicate         bool
		wantURL           string
	}{
		{"selected", "second", "https", true, "https://second.example.invalid/login"},
		{"stale id", "old", "https", true, ""},
		{"wrong subtype", "second", "other", true, ""},
		{"ambiguous legacy", "", "", true, ""},
		{"unique legacy", "", "", false, "https://second.example.invalid/login"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/passport/v1/public/authConfig" {
					t.Errorf("login must stop before any further protocol step")
					w.WriteHeader(500)
					return
				}
				first := ""
				if tc.duplicate {
					first = `{"authType":"auth/httpsOauth2","loginDomain":"realm","authId":"first","subType":"https","loginUrl":"https://first.example.invalid/login"},`
				}
				fmt.Fprintf(w, `{"code":0,"data":{"isLogin":0,"authServerInfoList":[%s{"authType":"auth/httpsOauth2","loginDomain":"realm","authId":"second","subType":"https","loginUrl":"https://second.example.invalid/login"}]}}`, first)
			}))
			defer server.Close()
			session := newTLSTestSession(server)
			defer session.Close()
			chosen := ""
			_, err := session.Login(HTTPSOauth2Login{Domain: "realm"}, LoginOptions{
				AuthID: tc.id, SubType: tc.subtype,
				ChallengeHandler: authchallenge.HandlerFuncs{ExternalLogin: func(c authchallenge.ExternalLoginChallenge) (authchallenge.ExternalLoginResponse, error) {
					chosen = c.LoginURL
					return authchallenge.ExternalLoginResponse{}, context.Canceled
				}},
			})
			if chosen != tc.wantURL {
				t.Fatalf("chosen login origin %q, want %q", chosen, tc.wantURL)
			}
			if tc.wantURL == "" && !errors.Is(err, ErrAuthMethodChanged) {
				t.Fatalf("stale/ambiguous identity: %v", err)
			}
			if tc.wantURL != "" && !errors.Is(err, context.Canceled) {
				t.Fatalf("selected login should reach the host challenge: %v", err)
			}
		})
	}
}
