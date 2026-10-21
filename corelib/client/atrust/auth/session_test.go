package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoginReturnsRefreshedCookiesForExistingSession(t *testing.T) {
	const deviceID = "saved-\"device\n"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/passport/v1/public/authConfig":
			cookie, err := r.Cookie("sid")
			if err != nil || cookie.Value != "stored-session-cookie" {
				t.Errorf("authConfig sid cookie = %#v, %v", cookie, err)
			}
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "refreshed-session-cookie", Path: "/"})
			fmt.Fprint(w, "{\"data\":{\"isLogin\":1,\"csrfToken\":\"csrf\"}}")
		case "/passport/v1/user/onlineInfo":
			fmt.Fprint(w, "{\"code\":0,\"data\":{\"username\":\"student\"}}")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "https://")
	session := newTLSTestSession(server)
	result, err := session.Login(nil, LoginOptions{
		DeviceID: deviceID,
		Cookies: []Cookie{{
			Host:   host,
			Scheme: "https",
			Name:   "sid",
			Value:  "stored-session-cookie",
		}},
	})
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	environment, decodeErr := base64.StdEncoding.DecodeString(session.env)
	var device struct {
		DeviceID string `json:"deviceId"`
	}
	if decodeErr != nil || json.Unmarshal(environment, &device) != nil || device.DeviceID != deviceID {
		t.Fatal("restored device identity does not produce a valid authentication environment")
	}
	if result.Username != "student" {
		t.Fatalf("Username = %q, want student", result.Username)
	}
	if result.SID != "refreshed-session-cookie" {
		t.Fatalf("SID = %q, want refreshed-session-cookie", result.SID)
	}

	var sid string
	for _, cookie := range result.Cookies {
		if cookie.Name == "sid" {
			sid = cookie.Value
			break
		}
	}
	if sid != "refreshed-session-cookie" {
		t.Fatalf("returned sid cookie = %q, want refreshed-session-cookie", sid)
	}
}

func TestPasswordLoginRequestsMissingCredentialsBeforePosting(t *testing.T) {
	for _, method := range []PasswordLogin{{Username: "alice"}, {Password: "secret"}} {
		t.Run(method.Username, func(t *testing.T) {
			posts := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPost {
					posts++
					t.Error("missing credentials were posted")
				}
				fmt.Fprint(w, `{"code":0,"data":{"isLogin":0,"authServerInfoList":[{"authType":"auth/psw","loginDomain":""}]}}`)
			}))
			defer server.Close()
			session := newTLSTestSession(server)
			_, err := session.Login(method, LoginOptions{DeviceID: "device"})
			if !errors.Is(err, ErrCredentialsRequired) || posts != 0 {
				t.Fatalf("missing credentials: posts=%d err=%v", posts, err)
			}
		})
	}
}
