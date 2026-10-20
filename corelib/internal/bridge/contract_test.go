package bridge

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const configJSON = "{\"schema_version\":1,\"server\":{\"host\":\"vpn.example.invalid\",\"port\":443},\"auth\":{\"method\":\"auth/psw\",\"username\":\"alice\",\"password\":\"private-password\"},\"listeners\":{\"socks\":\"127.0.0.1:1080\",\"http\":\"[::1]:1081\"}}"

func TestConfigBoundary(t *testing.T) {
	if _, status := ParseConfig([]byte(configJSON)); status != OK {
		t.Fatal(status)
	}
	for _, input := range []string{
		"", "null", "[]", configJSON + " {}",
		strings.Replace(configJSON, "\"schema_version\":1", "\"schema_version\":2", 1),
		strings.Replace(configJSON, "\"schema_version\":1", "\"schema_version\":1,\"schema_version\":1", 1),
		strings.Replace(configJSON, "\"schema_version\":1", "\"Schema_version\":1", 1),
		strings.Replace(configJSON, "\"server\":", "\"unknown\":", 1),
		strings.Replace(configJSON, "vpn.example.invalid", "https://vpn.example.invalid/path", 1),
		strings.Replace(configJSON, "vpn.example.invalid", "vpn.example.invalid:443", 1),
		strings.Replace(configJSON, "vpn.example.invalid", "-bad.example", 1),
		strings.Replace(configJSON, ":443", ":65536", 1),
		strings.Replace(configJSON, ":443", ":0", 1),
		strings.Replace(configJSON, "auth/psw", "easyconnect", 1),
		strings.Replace(configJSON, "127.0.0.1:1080", "0.0.0.0:1080", 1),
		strings.Replace(configJSON, "127.0.0.1:1080", "localhost:1080", 1),
		strings.Replace(configJSON, "private-password", "\\u0000", 1),
		strings.Replace(configJSON, "private-password", "\\ud800", 1),
		strings.Replace(configJSON, "private-password", string([]byte{0xff}), 1),
		strings.Replace(configJSON, "\"password\":\"private-password\"", "\"password\":null", 1),
		strings.Replace(configJSON, "private-password", strings.Repeat("x", 4097), 1),
		strings.Repeat(" ", MaxInput+1),
	} {
		c, status := ParseConfig([]byte(input))
		if status != InvalidArgument || c.Auth.Password != "" {
			t.Fatalf("invalid configuration accepted: status=%d", status)
		}
	}
}

func TestAuthenticationValidation(t *testing.T) {
	for _, kind := range []string{"sms", "totp", "radius", "text_captcha", "click_captcha", "cas", "oauth2"} {
		t.Run(kind, func(t *testing.T) {
			c := Challenge{Kind: kind}
			r := Response{Action: "submit"}
			switch kind {
			case "sms", "totp", "radius":
				r.Code = "123456"
			case "text_captcha":
				c.Image = []byte("image")
				r.Code = "ABCD"
			case "click_captcha":
				c.Image = []byte("image")
				r.Points = []Point{{X: 10, Y: 10}}
				r.Width = 100
				r.Height = 100
			case "cas", "oauth2":
				c.LoginURL = "https://vpn.example.invalid/login"
				r.CallbackURL = "https://vpn.example.invalid/callback?ticket=secret"
			}
			if !c.valid() || !r.valid(c) {
				t.Fatal("valid challenge/response rejected")
			}
			r.Action = "invented"
			if r.valid(c) {
				t.Fatal("unknown action accepted")
			}
			r = Response{Action: "cancel"}
			if !r.valid(c) {
				t.Fatal("cancellation rejected")
			}
			r.Code = "secret"
			if r.valid(c) {
				t.Fatal("cancel with credentials accepted")
			}
		})
	}
	if (Challenge{Kind: "unknown"}).valid() || (Challenge{Kind: "text_captcha", Image: make([]byte, 131073)}).valid() {
		t.Fatal("invalid challenge accepted")
	}
	if (Response{Action: "submit", SkipSecondaryAuth: true}).valid(Challenge{Kind: "sms"}) {
		t.Fatal("skip granted without capability")
	}
	if !(Response{Action: "submit", SkipSecondaryAuth: true}).valid(Challenge{Kind: "sms", CanSkipSecondaryAuth: true}) {
		t.Fatal("supported skip rejected")
	}
	if (Response{Action: "submit", SkipSecondaryAuth: true, Code: "123456"}).valid(Challenge{Kind: "sms", CanSkipSecondaryAuth: true}) {
		t.Fatal("ambiguous skip and code accepted")
	}
	if (Response{Action: "submit", Width: 10, Height: 10, Points: []Point{{X: 10, Y: 1}}}).valid(Challenge{Kind: "click_captcha"}) {
		t.Fatal("out of bounds point accepted")
	}
	if validURL("file:///secret") || validURL("https://user:secret@example.invalid") {
		t.Fatal("unsafe login URL accepted")
	}
}

func FuzzConfiguration(f *testing.F) {
	f.Add([]byte(configJSON))
	f.Add([]byte("{\"schema_version\":1,\"server\":null}"))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, status := ParseConfig(data)
		if status == OK {
			out, err := json.Marshal(c)
			if err != nil || !json.Valid(out) || !bytes.Contains(out, []byte("\"schema_version\":1")) {
				t.Fatal("unstable config")
			}
		}
	})
}
