// Package bridge owns the versioned host contract, independently of VPN protocols.
package bridge

import (
	"bytes"
	"encoding/json"
	"io"
	"net/netip"
	"net/url"
	"strings"
	"unicode/utf8"
)

type Status int32

func (s Status) Message() string {
	switch s {
	case OK:
		return "Session ended"
	case Timeout:
		return "Operation timed out"
	case Unsupported:
		return "Embedded VPN session is not available"
	case Cancelled:
		return "Session cancelled"
	case Limit:
		return "Resource limit reached"
	default:
		return "Core operation failed"
	}
}

type Config struct {
	SchemaVersion int `json:"schema_version"`
	Server        struct {
		Host string `json:"host"`
		Port uint16 `json:"port"`
	} `json:"server"`
	Auth struct {
		Method     string `json:"method"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		Phone      string `json:"phone"`
		Domain     string `json:"domain"`
		TOTPSecret string `json:"totp_secret"`
	} `json:"auth"`
	Listeners struct {
		SOCKS string `json:"socks"`
		HTTP  string `json:"http"`
	} `json:"listeners"`
}

// Decode rejects ambiguous objects and never returns parser text containing secrets.
func decode(data []byte, target any) bool {
	if len(data) == 0 || len(data) > MaxInput || !utf8.Valid(data) {
		return false
	}
	tokens := json.NewDecoder(bytes.NewReader(data))
	tokens.UseNumber()
	if !scanValue(tokens, 0) {
		return false
	}
	if _, err := tokens.Token(); err != io.EOF {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	return decoder.Decode(target) == nil
}

func scanValue(d *json.Decoder, depth int) bool {
	if depth > MaxJSONDepth {
		return false
	}
	t, err := d.Token()
	if err != nil || t == nil {
		return false
	}
	switch t {
	case json.Delim('{'):
		keys := make(map[string]bool)
		for d.More() {
			key, err := d.Token()
			name, ok := key.(string)
			if err != nil || !ok || keys[name] {
				return false
			}
			for _, c := range name {
				if c != '_' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
					return false
				}
			}
			keys[name] = true
			if !scanValue(d, depth+1) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && end == json.Delim('}')
	case json.Delim('['):
		for d.More() {
			if !scanValue(d, depth+1) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && end == json.Delim(']')
	}
	if text, ok := t.(string); ok {
		return !strings.ContainsAny(text, "\x00\ufffd")
	}
	_, delimiter := t.(json.Delim)
	return !delimiter
}

func ParseConfig(data []byte) (Config, Status) {
	var c Config
	if !decode(data, &c) || c.SchemaVersion != ABIVersion || c.Server.Port == 0 || !validHost(c.Server.Host) {
		return Config{}, InvalidArgument
	}
	switch c.Auth.Method {
	case "", "auth/psw", "auth/smsCheckCode", "auth/cas", "auth/httpsOauth2":
	default:
		return Config{}, InvalidArgument
	}
	if len(c.Auth.Username) > MaxUsername || len(c.Auth.Password) > MaxPassword ||
		len(c.Auth.Phone) > MaxPhone || len(c.Auth.Domain) > MaxDomain || len(c.Auth.TOTPSecret) > MaxTOTPSecret ||
		!validListener(c.Listeners.SOCKS) || !validListener(c.Listeners.HTTP) {
		return Config{}, InvalidArgument
	}
	return c, OK
}

func validHost(host string) bool {
	if _, err := netip.ParseAddr(host); err == nil {
		return true
	}
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

func validListener(address string) bool {
	if address == "" {
		return true
	}
	endpoint, err := netip.ParseAddrPort(address)
	return err == nil && endpoint.Addr().IsLoopback() && endpoint.Port() != 0
}

type Point struct {
	X int `json:"x"`
	Y int `json:"y"`
}

type Response struct {
	SchemaVersion     int     `json:"schema_version"`
	Generation        uint64  `json:"generation,string"`
	RequestID         uint64  `json:"request_id,string"`
	Action            string  `json:"action"`
	Code              string  `json:"code"`
	SkipSecondaryAuth bool    `json:"skip_secondary_auth"`
	Points            []Point `json:"points"`
	Width             int     `json:"width"`
	Height            int     `json:"height"`
	CallbackURL       string  `json:"callback_url"`
}

type Challenge struct {
	Kind                 string `json:"kind"`
	Image                []byte `json:"image,omitempty"`
	LoginURL             string `json:"login_url,omitempty"`
	CanSkipSecondaryAuth bool   `json:"can_skip_secondary_auth,omitempty"`
}

func (c Challenge) valid() bool {
	if len(c.Image) > MaxAuthImage {
		return false
	}
	switch c.Kind {
	case "sms", "totp", "radius":
		return len(c.Image) == 0 && c.LoginURL == ""
	case "text_captcha", "click_captcha":
		return len(c.Image) > 0 && c.LoginURL == "" && !c.CanSkipSecondaryAuth
	case "cas", "oauth2":
		return validURL(c.LoginURL) && len(c.Image) == 0 && !c.CanSkipSecondaryAuth
	default:
		return false
	}
}

func validURL(value string) bool {
	if len(value) > MaxURL || strings.ContainsRune(value, 0) {
		return false
	}
	u, err := url.Parse(value)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Hostname() != "" && u.User == nil
}

func (r Response) valid(c Challenge) bool {
	if r.Action == "cancel" {
		return r.Code == "" && !r.SkipSecondaryAuth && len(r.Points) == 0 && r.Width == 0 && r.Height == 0 && r.CallbackURL == ""
	}
	if r.Action != "submit" {
		return false
	}
	switch c.Kind {
	case "sms", "totp", "radius", "text_captcha":
		return (strings.TrimSpace(r.Code) != "" || (r.SkipSecondaryAuth && c.CanSkipSecondaryAuth)) &&
			(!r.SkipSecondaryAuth || r.Code == "") &&
			len(r.Code) <= MaxAuthCode && (!r.SkipSecondaryAuth || c.CanSkipSecondaryAuth) &&
			len(r.Points) == 0 && r.Width == 0 && r.Height == 0 && r.CallbackURL == ""
	case "click_captcha":
		if r.Code != "" || r.SkipSecondaryAuth || r.CallbackURL != "" || r.Width < 1 || r.Height < 1 ||
			r.Width > MaxAuthDimension || r.Height > MaxAuthDimension || len(r.Points) == 0 || len(r.Points) > MaxAuthPoints {
			return false
		}
		for _, p := range r.Points {
			if p.X < 0 || p.Y < 0 || p.X >= r.Width || p.Y >= r.Height {
				return false
			}
		}
		return true
	case "cas", "oauth2":
		return validURL(r.CallbackURL) && r.Code == "" && !r.SkipSecondaryAuth && len(r.Points) == 0 && r.Width == 0 && r.Height == 0
	}
	return false
}
