// Package bridge owns the versioned host contract, independently of VPN protocols.
package bridge

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"github.com/wtalioy/JustConnect/corelib"
	"github.com/wtalioy/JustConnect/corelib/policy"
	"github.com/wtalioy/JustConnect/corelib/resolve"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
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
	case AuthUnsupported:
		return "Server requires an unsupported authentication step"
	case PermissionDenied:
		return "Network operation requires permission"
	case SessionInvalid:
		return "Session expired; reconnect to authenticate"
	case CredentialsRequired:
		return "Login credentials are required"
	case AuthMethodChanged:
		return "Authentication identity changed; query methods again"
	case TLSTrust:
		return "TLS certificate is not trusted"
	case TLSProtocol:
		return "TLS protocol negotiation failed"
	case NetworkFailure:
		return "Network connection failed"
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
	SchemaVersion int               `json:"schema_version"`
	Operation     string            `json:"operation"`
	Protection    *ProtectionConfig `json:"protection,omitempty"`
	initialPolicy *policy.ProtectionPolicy
	originalDNS   *resolve.OriginalDNS
	Server        struct {
		Host string `json:"host"`
		Port uint16 `json:"port"`
	} `json:"server"`
	TLS struct {
		SkipVerify           bool   `json:"skip_verify"`
		CAPEM                string `json:"ca_pem"`
		AllowUnverifiedNodes bool   `json:"allow_unverified_nodes"`
	} `json:"tls"`
	Auth struct {
		AuthID     string `json:"auth_id"`
		SubType    string `json:"sub_type"`
		Method     string `json:"method"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		Phone      string `json:"phone"`
		Domain     string `json:"domain"`
		TOTPSecret string `json:"totp_secret"`
	} `json:"auth"`
	AuthenticationCache struct {
		Enabled bool   `json:"enabled"`
		Account string `json:"account"`
		Data    []byte `json:"data,omitempty"`
	} `json:"authentication_cache"`
	Network struct {
		Interface        string                     `json:"interface"`
		AutoDetect       bool                       `json:"auto_detect"`
		LocalDNS         string                     `json:"local_dns"`
		SecondaryDNS     string                     `json:"secondary_dns"`
		DNSCacheTTL      uint32                     `json:"dns_cache_ttl"`
		DisableRemoteDNS bool                       `json:"disable_remote_dns"`
		Language         string                     `json:"language"`
		OriginalDNS      []resolve.OriginalDNSRoute `json:"original_dns,omitempty"`
	} `json:"network"`
	KeepAlive struct {
		Mode string `json:"mode"`
		URL  string `json:"url"`
	} `json:"keepalive"`
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
	if len(c.TLS.CAPEM) > MaxCAPEM || (c.TLS.CAPEM != "" && !x509.NewCertPool().AppendCertsFromPEM([]byte(c.TLS.CAPEM))) {
		return Config{}, InvalidArgument
	}
	if corelib.ValidateKeepAlive(c.KeepAlive.Mode, c.KeepAlive.URL) != nil {
		return Config{}, InvalidArgument
	}
	cache := c.AuthenticationCache
	if len(cache.Account) > MaxUsername || len(cache.Data) > MaxAuthCache ||
		(cache.Account == "") != (len(cache.Data) == 0) || (!cache.Enabled && len(cache.Data) != 0) ||
		(c.Operation == "auth_methods" && cache.Enabled) {
		return Config{}, InvalidArgument
	}
	if c.Operation != "" && c.Operation != "connect" && c.Operation != "auth_methods" {
		return Config{}, InvalidArgument
	}
	if c.Protection != nil {
		if c.Operation == "auth_methods" || c.Protection.Protected == nil || c.Protection.Campus == nil {
			return Config{}, InvalidArgument
		}
		initial, err := policy.NewProtectionPolicy(c.Protection.Protected, c.Protection.Campus, c.Protection.ProtectedNames, c.Protection.CampusNames)
		if err != nil {
			return Config{}, InvalidArgument
		}
		c.initialPolicy = &initial
	}
	if len(c.Network.Interface) > MaxInterfaceName || len(c.Network.Language) > MaxLanguage || !validDNS(c.Network.LocalDNS) {
		return Config{}, InvalidArgument
	}
	if len(c.Network.OriginalDNS) != 0 {
		if c.Operation == "auth_methods" || c.Protection == nil {
			return Config{}, InvalidArgument
		}
		var err error
		c.originalDNS, err = compileOriginalDNS(c.Network.OriginalDNS)
		if err != nil {
			return Config{}, InvalidArgument
		}
	}
	if c.Network.SecondaryDNS != "" {
		if _, err := netip.ParseAddr(c.Network.SecondaryDNS); err != nil {
			return Config{}, InvalidArgument
		}
	}
	switch c.Auth.Method {
	case "", "auth/psw", "auth/smsCheckCode", "auth/cas", "auth/httpsOauth2":
	default:
		return Config{}, InvalidArgument
	}
	if len(c.Auth.AuthID) > MaxDomain || len(c.Auth.SubType) > MaxDomain || len(c.Auth.Username) > MaxUsername || len(c.Auth.Password) > MaxPassword ||
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

func validDNS(address string) bool {
	if address == "" {
		return true
	}
	if _, err := netip.ParseAddr(address); err == nil {
		return true
	}
	endpoint, err := netip.ParseAddrPort(address)
	return err == nil && endpoint.Port() != 0
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
	Points            []Point `json:"points,omitempty"`
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
	case "trusted_device":
		return len(c.Image) == 0 && c.LoginURL == "" && !c.CanSkipSecondaryAuth
	case "sms", "totp", "radius":
		return len(c.Image) == 0 && c.LoginURL == ""
	case "text_captcha", "click_captcha":
		if c.LoginURL != "" || c.CanSkipSecondaryAuth {
			return false
		}
		config, format, err := image.DecodeConfig(bytes.NewReader(c.Image))
		return err == nil && (format == "png" || format == "jpeg" || format == "gif") &&
			config.Width > 0 && config.Height > 0 && config.Width <= MaxAuthDimension && config.Height <= MaxAuthDimension && int64(config.Width)*int64(config.Height) <= MaxAuthPixels
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

func (r Response) emptyInput() bool {
	return r.Code == "" && !r.SkipSecondaryAuth && len(r.Points) == 0 && r.Width == 0 && r.Height == 0 && r.CallbackURL == ""
}

func (r Response) valid(c Challenge) bool {
	if r.Action == "cancel" {
		return r.emptyInput()
	}
	if c.Kind == "trusted_device" {
		return r.Action == "confirm" && r.emptyInput()
	}
	if r.Action != "submit" {
		return false
	}
	switch c.Kind {
	case "sms", "totp", "radius", "text_captcha":
		return (strings.TrimSpace(r.Code) != "" || (r.SkipSecondaryAuth && c.CanSkipSecondaryAuth)) &&
			len(r.Code) <= MaxAuthCode && (!r.SkipSecondaryAuth || c.CanSkipSecondaryAuth) &&
			len(r.Points) == 0 && r.Width == 0 && r.Height == 0 && r.CallbackURL == ""
	case "click_captcha":
		if r.Code != "" || r.SkipSecondaryAuth || r.CallbackURL != "" || r.Width < 1 || r.Height < 1 ||
			r.Width > MaxAuthDimension || r.Height > MaxAuthDimension || int64(r.Width)*int64(r.Height) > MaxAuthPixels || len(r.Points) == 0 || len(r.Points) > MaxAuthPoints {
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

type AuthMethod struct {
	AuthID   string `json:"auth_id,omitempty"`
	SubType  string `json:"sub_type,omitempty"`
	Type     string `json:"type"`
	Domain   string `json:"domain"`
	Name     string `json:"name"`
	LoginURL string `json:"login_url,omitempty"`
}
