package atrust

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/wtalioy/JustConnect/corelib/client/atrust/auth"
)

func cacheIdentity(options SetupOptions, serverHost, username string) auth.ClientIdentity {
	identity := auth.ClientIdentity{ServerHost: strings.ToLower(serverHost), Username: username, AuthID: options.AuthID, AuthSubType: options.AuthSubType}
	if options.LoginMethod != nil {
		identity.AuthType = options.LoginMethod.AuthType()
		identity.LoginDomain = options.LoginMethod.LoginDomain()
	}
	switch method := options.LoginMethod.(type) {
	case auth.PasswordLogin:
		identity.LoginUsername = method.Username
	case *auth.PasswordLogin:
		identity.LoginUsername = method.Username
	case auth.SMSLogin:
		identity.Phone = method.Phone
	case *auth.SMSLogin:
		identity.Phone = method.Phone
	}
	return identity
}

func cachedClientData(encoded []byte, expected auth.ClientIdentity) (auth.ClientAuthData, bool) {
	var data auth.ClientAuthData
	if len(encoded) == 0 || json.Unmarshal(encoded, &data) != nil || expected.Username == "" || data.Identity != expected || data.DeviceID == "" || len(data.Cookies) == 0 {
		return auth.ClientAuthData{}, false
	}
	if _, err := auth.ParseServerVersionInfo(data.ServerVersionInfo); err != nil {
		return auth.ClientAuthData{}, false
	}
	names := make(map[string]bool)
	for _, cookie := range data.Cookies {
		value := http.Cookie{Name: cookie.Name, Value: cookie.Value}
		if !strings.EqualFold(cookie.Host, expected.ServerHost) || cookie.Scheme != "https" || names[cookie.Name] || value.Valid() != nil || (cookie.Name == "sid" && cookie.Value == "") {
			return auth.ClientAuthData{}, false
		}
		names[cookie.Name] = true
	}
	if !names["sid"] {
		return auth.ClientAuthData{}, false
	}
	return data, true
}
