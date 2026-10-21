package bridge

import (
	"bytes"
	"encoding/json"
	"image"
	"image/gif"
	"image/jpeg"
	"image/png"
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
		strings.Replace(configJSON, "\"schema_version\":1", "\"schema_version\":1,\"tls\":{\"ca_pem\":\"not a certificate\"}", 1),
		strings.Replace(configJSON, "\"schema_version\":1", "\"schema_version\":1,\"tls\":{\"ca_pem\":\""+strings.Repeat("x", MaxCAPEM+1)+"\"}", 1),
	} {
		c, status := ParseConfig([]byte(input))
		if status != InvalidArgument || c.Auth.Password != "" {
			t.Fatalf("invalid configuration accepted: status=%d", status)
		}
	}
}

func TestAuthenticationCacheInputBoundary(t *testing.T) {
	var original Config
	if json.Unmarshal([]byte(configJSON), &original) != nil {
		t.Fatal("fixture")
	}
	original.AuthenticationCache.Enabled = true
	original.AuthenticationCache.Account = "canonical-account"
	original.AuthenticationCache.Data = []byte("opaque\x00bytes")
	encoded := configBytes(t, original)
	restored, status := ParseConfig(encoded)
	if status != OK || restored.AuthenticationCache.Account != "canonical-account" || !bytes.Equal(restored.AuthenticationCache.Data, original.AuthenticationCache.Data) {
		t.Fatal("cache input did not round trip")
	}
	for _, mutate := range []func(*Config){
		func(c *Config) { c.AuthenticationCache.Enabled = false },
		func(c *Config) { c.AuthenticationCache.Account = "" },
		func(c *Config) { c.AuthenticationCache.Data = nil },
		func(c *Config) { c.AuthenticationCache.Data = bytes.Repeat([]byte("x"), MaxAuthCache+1) },
		func(c *Config) { c.AuthenticationCache.Account = strings.Repeat("x", MaxUsername+1) },
		func(c *Config) { c.Operation = "auth_methods" },
	} {
		bad := original
		mutate(&bad)
		parsed, status := ParseConfig(configBytes(t, bad))
		if status != InvalidArgument || len(parsed.AuthenticationCache.Data) != 0 {
			t.Fatal("invalid cache input accepted or retained")
		}
	}
	broken := bytes.Replace(encoded, []byte(`"data":"b3BhcXVlAGJ5dGVz"`), []byte(`"data":"invalid?"`), 1)
	if bytes.Equal(encoded, broken) {
		t.Fatal("base64 fixture did not change")
	}
	if _, status := ParseConfig(broken); status != InvalidArgument {
		t.Fatal("invalid base64 accepted")
	}
}

func TestAuthenticationValidation(t *testing.T) {
	for _, kind := range []string{"sms", "totp", "radius", "text_captcha", "click_captcha", "cas", "oauth2", "trusted_device"} {
		t.Run(kind, func(t *testing.T) {
			c := Challenge{Kind: kind}
			r := Response{Action: "submit"}
			switch kind {
			case "trusted_device":
				r.Action = "confirm"
			case "sms", "totp", "radius":
				r.Code = "123456"
			case "text_captcha":
				c.Image = captchaImage(t, 100, 100, "png")
				r.Code = "ABCD"
			case "click_captcha":
				c.Image = captchaImage(t, 100, 100, "png")
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
	if !(Response{Action: "submit", SkipSecondaryAuth: true, Code: "123456"}).valid(Challenge{Kind: "sms", CanSkipSecondaryAuth: true}) {
		t.Fatal("protocol code with secondary-auth flag rejected")
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

func TestTrustedDeviceConfirmationCannotBeInferred(t *testing.T) {
	c := Challenge{Kind: "trusted_device"}
	for _, r := range []Response{{Action: "submit"}, {Action: "submit", Code: "yes"}, {Action: "confirm", Code: "yes"}, {Action: "confirm", SkipSecondaryAuth: true}, {Action: "confirm", CallbackURL: "https://gateway.test"}, {Action: "confirm", Width: 1}, {Action: "confirm", Points: []Point{{X: 0, Y: 0}}}} {
		if r.valid(c) {
			t.Fatal("non-explicit or mixed confirmation accepted")
		}
	}
	if (Response{Action: "confirm"}).valid(Challenge{Kind: "sms"}) {
		t.Fatal("confirmation accepted for a code request")
	}
}

func captchaImage(t *testing.T, width, height int, format string) []byte {
	t.Helper()
	var data bytes.Buffer
	img := image.NewGray(image.Rect(0, 0, width, height))
	var err error
	switch format {
	case "png":
		err = png.Encode(&data, img)
	case "jpeg":
		err = jpeg.Encode(&data, img, nil)
	case "gif":
		err = gif.Encode(&data, img, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func TestAuthenticationImageResourcesAreBounded(t *testing.T) {
	for _, format := range []string{"png", "jpeg", "gif"} {
		if !(Challenge{Kind: "text_captcha", Image: captchaImage(t, 40, 20, format)}).valid() {
			t.Fatalf("valid %s image rejected", format)
		}
	}
	for _, data := range [][]byte{nil, []byte("not an image"), make([]byte, MaxAuthImage+1), captchaImage(t, 8193, 1, "png"), captchaImage(t, 1, 8193, "png"), captchaImage(t, 2049, 2048, "png")} {
		if (Challenge{Kind: "click_captcha", Image: data}).valid() {
			t.Fatal("malformed or oversized image accepted")
		}
	}
	if (Response{Action: "submit", Width: 2049, Height: 2048, Points: []Point{{X: 1, Y: 1}}}).valid(Challenge{Kind: "click_captcha"}) {
		t.Fatal("oversized response canvas accepted")
	}
}
