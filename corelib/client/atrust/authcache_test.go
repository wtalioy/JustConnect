package atrust

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/wtalioy/JustConnect/corelib/client/atrust/auth"
)

func TestCachedClientDataRejectsInvalidScopesAndMaterial(t *testing.T) {
	expected := auth.ClientIdentity{ServerHost: "vpn.example.invalid:443", Username: "alice", AuthID: "opaque-id", AuthSubType: "sms", AuthType: "auth/smsCheckCode", LoginDomain: "id.example.invalid", Phone: "86-123456"}
	changes := map[string]func(*auth.ClientAuthData){
		"valid empty auxiliary": func(d *auth.ClientAuthData) {
			d.Cookies = append(d.Cookies, auth.Cookie{Host: expected.ServerHost, Scheme: "https", Name: "optional", Value: ""})
		},
		"valid cookie host case": func(d *auth.ClientAuthData) { d.Cookies[0].Host = strings.ToUpper(expected.ServerHost) },
		"valid":                  func(*auth.ClientAuthData) {},
		"server":                 func(d *auth.ClientAuthData) { d.Identity.ServerHost = "other.example.invalid:443" },
		"port":                   func(d *auth.ClientAuthData) { d.Identity.ServerHost = "vpn.example.invalid:8443" },
		"login account":          func(d *auth.ClientAuthData) { d.Identity.LoginUsername = "other-login" },
		"account":                func(d *auth.ClientAuthData) { d.Identity.Username = "other-user" },
		"method":                 func(d *auth.ClientAuthData) { d.Identity.AuthType = "auth/httpsOauth2" },
		"domain":                 func(d *auth.ClientAuthData) { d.Identity.LoginDomain = "other-domain" },
		"auth id":                func(d *auth.ClientAuthData) { d.Identity.AuthID = "other-id" },
		"subtype":                func(d *auth.ClientAuthData) { d.Identity.AuthSubType = "other-subtype" },
		"phone":                  func(d *auth.ClientAuthData) { d.Identity.Phone = "86-654321" },
		"old unbound":            func(d *auth.ClientAuthData) { d.Identity = auth.ClientIdentity{} },
		"cookie host":            func(d *auth.ClientAuthData) { d.Cookies[0].Host = "other.example.invalid:443" },
		"cookie port":            func(d *auth.ClientAuthData) { d.Cookies[0].Host = "vpn.example.invalid:8443" },
		"cookie scheme":          func(d *auth.ClientAuthData) { d.Cookies[0].Scheme = "http" },
		"cookie value":           func(d *auth.ClientAuthData) { d.Cookies[0].Value = "invalid\ncookie" },
		"duplicate cookie":       func(d *auth.ClientAuthData) { d.Cookies = append(d.Cookies, d.Cookies[0]) },
		"empty sid":              func(d *auth.ClientAuthData) { d.Cookies[0].Value = "" },
		"missing sid":            func(d *auth.ClientAuthData) { d.Cookies[0].Name = "other-cookie" },
		"empty device":           func(d *auth.ClientAuthData) { d.DeviceID = "" },
		"invalid manifest":       func(d *auth.ClientAuthData) { d.ServerVersionInfo = json.RawMessage(`{"code":1}`) },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			data := auth.ClientAuthData{Identity: expected, DeviceID: "saved-device", Cookies: []auth.Cookie{{Host: expected.ServerHost, Scheme: "https", Name: "sid", Value: "saved-cookie"}}, ServerVersionInfo: json.RawMessage(`{"code":0,"data":{}}`)}
			change(&data)
			encoded, err := json.Marshal(data)
			if err != nil {
				t.Fatal(err)
			}
			decoded, okay := cachedClientData(encoded, expected)
			if okay != strings.HasPrefix(name, "valid") {
				t.Fatalf("accepted = %t", okay)
			}
			if !okay && (decoded.DeviceID != "" || len(decoded.Cookies) != 0 || len(decoded.ServerVersionInfo) != 0) {
				t.Fatal("rejected data exposed an old device, cookie or manifest")
			}
			if name == "valid" {
				anonymous := expected
				anonymous.Username = ""
				if _, okay := cachedClientData(encoded, anonymous); okay {
					t.Fatal("an anonymous account reused a bound cache")
				}
			}
		})
	}
}

func TestCacheIdentityIncludesPhoneForValueAndPointerMethods(t *testing.T) {
	for _, pointer := range []bool{false, true} {
		method := auth.SMSLogin{Phone: "86-123456", Domain: "id.example.invalid"}
		options := SetupOptions{AuthID: "id", AuthSubType: "sms", LoginMethod: method}
		if pointer {
			options.LoginMethod = &method
		}
		original := cacheIdentity(options, "VPN.example.invalid:443", "alice")
		data := auth.ClientAuthData{Identity: original, DeviceID: "device", ServerVersionInfo: json.RawMessage(`{"code":0}`), Cookies: []auth.Cookie{{Host: "vpn.example.invalid:443", Scheme: "https", Name: "sid", Value: "sid"}}}
		encoded, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		if _, okay := cachedClientData(encoded, original); !okay {
			t.Fatal("selected phone cannot restore its own cache")
		}
		method.Phone = "86-654321"
		if !pointer {
			options.LoginMethod = method
		}
		if _, okay := cachedClientData(encoded, cacheIdentity(options, "vpn.example.invalid:443", "alice")); okay {
			t.Fatal("changing the selected phone reused another phone's cache")
		}
	}
}

func TestCacheBindsLoginAliasSeparatelyFromConfirmedAccount(t *testing.T) {
	for _, pointer := range []bool{false, true} {
		method := auth.PasswordLogin{Username: "login-alias", Domain: "id.example.invalid"}
		options := SetupOptions{AuthID: "id", AuthSubType: "password", LoginMethod: method}
		if pointer {
			options.LoginMethod = &method
		}
		identity := cacheIdentity(options, "vpn.example.invalid:443", "canonical-account")
		data := auth.ClientAuthData{Identity: identity, DeviceID: "device", ServerVersionInfo: json.RawMessage(`{"code":0}`), Cookies: []auth.Cookie{{Host: identity.ServerHost, Scheme: "https", Name: "sid", Value: "sid"}}}
		encoded, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		if _, okay := cachedClientData(encoded, identity); !okay || identity.Username != "canonical-account" {
			t.Fatal("the confirmed account cannot restore its configured login alias")
		}
		method.Username = "different-login"
		if !pointer {
			options.LoginMethod = method
		}
		if _, okay := cachedClientData(encoded, cacheIdentity(options, "vpn.example.invalid:443", "canonical-account")); okay {
			t.Fatal("changing the login alias reused another login's cache")
		}
	}
}
