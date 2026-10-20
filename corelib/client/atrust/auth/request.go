package auth

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/wtalioy/JustConnect/corelib/client/authchallenge"
)

func (s *Session) ServerVersionInfo() ([]byte, error) {

	req, err := http.NewRequest(http.MethodGet, s.baseURL+"/public/manifest", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)

	resp, err := s.request(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("aTrust server manifest returned HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if _, err := ParseServerVersionInfo(body); err != nil {
		return nil, err
	}

	return body, nil
}

func (s *Session) authConfig(mod, needTicket bool) (int, []AuthInfo, error) {
	return s.authConfigContext(context.Background(), mod, needTicket, false)
}

func (s *Session) authConfigContext(ctx context.Context, mod, needTicket, refresh bool) (int, []AuthInfo, error) {

	params := WithSharedParams(nil)
	if mod {
		params.Set("mod", "1")
	}
	if needTicket {
		params.Set("needTicket", "1")
	} else if refresh {
		params.Set("needTicket", "0")
	}

	u := s.baseURL + "/passport/v1/public/authConfig"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u+"?"+params.Encode(), nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-rid", s.rid)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.request(req)
	if err != nil {
		return 0, nil, err
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return 0, nil, fmt.Errorf("%w: authConfig HTTP %d", ErrSessionInvalid, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, nil, fmt.Errorf("authConfig HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}

	var re struct {
		Code *int `json:"code"`
		Data struct {
			AuthServerInfoList []AuthInfo `json:"authServerInfoList"`
			IsLogin            *int       `json:"isLogin"`
			CSRF               string     `json:"csrfToken"`
			Security           struct {
				CSRF string `json:"csrfToken"`
			} `json:"security"`
			PubKey         string             `json:"pubKey"`
			PubKeyExp      string             `json:"pubKeyExp"`
			AntiReplayRand string             `json:"antiReplayRand"`
			AntiMITM       antiMITMAttackData `json:"antiMITMAttackData"`
		} `json:"data"`
	}
	err = json.Unmarshal(body, &re)
	if err != nil {
		return 0, nil, err
	}
	if re.Code != nil && *re.Code != 0 {
		if *re.Code == 10000004 || *re.Code == 75500002 {
			return 0, nil, fmt.Errorf("%w: authConfig code %d", ErrSessionInvalid, *re.Code)
		}
		return 0, nil, fmt.Errorf("authConfig failed with code %d", *re.Code)
	}
	if refresh && (re.Code == nil || re.Data.IsLogin == nil) {
		return 0, nil, fmt.Errorf("authConfig response missing code or isLogin")
	}
	if refresh && *re.Data.IsLogin != 1 {
		return 0, nil, ErrSessionInvalid
	}
	responseCSRFToken := re.Data.CSRF
	if responseCSRFToken == "" {
		responseCSRFToken = re.Data.Security.CSRF
	}
	if len(re.Data.AntiMITM.raw) != 0 {
		if err := s.checkAntiMITMAuthConfig(ctx, resp, re.Data.AntiMITM, responseCSRFToken); err != nil {
			// Official desktop and Android clients report this through their
			// event/UI layer, but their authentication callers continue.
			if s.Diagnostic != nil {
				s.Diagnostic("anti_mitm_failed")
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, nil, err
	}

	s.csrfToken = responseCSRFToken
	s.pubKey = re.Data.PubKey
	s.pubKeyExp = re.Data.PubKeyExp
	s.antiReplayRand = re.Data.AntiReplayRand

	isLogin := 0
	if re.Data.IsLogin != nil {
		isLogin = *re.Data.IsLogin
	}
	return isLogin, re.Data.AuthServerInfoList, nil
}

func (s *Session) checkAntiMITMAuthConfig(ctx context.Context, resp *http.Response, data antiMITMAttackData, csrfToken string) error {
	if err := verifySangforChallenge(data); err != nil {
		return err
	}
	if err := verifySangforMITMSignature(data); err != nil {
		return err
	}
	if data.Enable != 1 {
		return nil
	}
	if resp.TLS == nil {
		return fmt.Errorf("aTrust anti-MITM verification failed: response was not received over TLS")
	}
	if err := verifySangforCertificateIdentity(resp.TLS.PeerCertificates, data); err != nil {
		return err
	}
	if data.AntiMITMRequest {
		return nil
	}
	return s.performAntiMITMRequestContext(ctx, data, csrfToken)
}

func (s *Session) performAntiMITMRequestContext(ctx context.Context, data antiMITMAttackData, csrfToken string) error {
	nonce, err := sangforNonce()
	if err != nil {
		return fmt.Errorf("aTrust anti-MITM request failed: generate nonce: %w", err)
	}
	payload := []byte(fmt.Sprintf("\n            {\n                \"nonce\": \"%s\",\n                \"ticket\": \"%s\"\n            }\n        ", nonce, data.Ticket))

	params := WithSharedParams(nil)
	if s.deviceID != "" {
		params.Set("mobileId", s.deviceID)
	}
	u := s.baseURL + "/controller/v1/public/antiMITMRequest"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u+"?"+params.Encode(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-csrf-token", csrfToken)
	req.Header.Set("x-sdp-rid", s.rid)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.request(req)
	if err != nil {
		return fmt.Errorf("aTrust anti-MITM request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("aTrust anti-MITM request failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("aTrust anti-MITM request failed with HTTP status %d", resp.StatusCode)
	}

	var result struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Nonce          string `json:"nonce"`
			AntiMITMEnable int    `json:"antiMITMEnable"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("aTrust anti-MITM request failed: invalid response: %w", err)
	}
	if result.Data.Nonce != nonce {
		return fmt.Errorf("aTrust anti-MITM request nonce mismatch")
	}
	if result.Code == 10000004 {
		return fmt.Errorf("aTrust anti-MITM request denied: session not found")
	}
	if result.Code == 10000008 {
		return fmt.Errorf("aTrust anti-MITM request detected a MITM attack")
	}

	expected := sangforHMAC(sangforSignatureKey(data), body)
	actual := strings.ToUpper(resp.Header.Get("X-Response-Sig"))
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return fmt.Errorf("aTrust anti-MITM response signature mismatch")
	}
	return nil
}

func (s *Session) reportEnv() error {

	u := s.baseURL + "/controller/v1/public/reportEnv"

	if s.ticket == "" {
		return fmt.Errorf("ticket is empty")
	}

	payload := map[string]interface{}{
		"ticket":   s.ticket,
		"deviceId": s.deviceID,
		"env": map[string]interface{}{
			"endpoint": map[string]interface{}{
				"device_id": s.deviceID,
				"device": map[string]interface{}{
					"type": "browser",
				},
			},
		},
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", u+"?"+WithSharedParams(nil).Encode(), bytes.NewReader(body))
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.request(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ = io.ReadAll(resp.Body)

	var re struct {
		Code int `json:"code"`
	}

	err = json.Unmarshal(body, &re)
	if err != nil {
		return err
	}

	if re.Code != 0 {

		return fmt.Errorf("reportEnv failed with code %d", re.Code)
	}

	return nil
}

type smsMode uint8

const (
	smsModeUnknown smsMode = iota
	smsWithoutAuthID
	smsWithAuthID
)

type authServiceInfo struct {
	AuthID   string `json:"authId"`
	AuthType string `json:"authType"`
	SubType  string `json:"subType"`
}

type authStepData struct {
	NextService     string            `json:"nextService"`
	NextServiceList []authServiceInfo `json:"nextServiceList"`
}

type authStep struct {
	Service string
	AuthID  string
	SMSMode smsMode
}

func authStepFromData(data authStepData) authStep {
	step := authStep{Service: data.NextService}

	var selected *authServiceInfo
	for i := range data.NextServiceList {
		service := &data.NextServiceList[i]
		if step.Service != "" && service.AuthType == step.Service {
			selected = service
			break
		}
	}
	if selected == nil && len(data.NextServiceList) > 0 {
		selected = &data.NextServiceList[0]
	}

	if selected != nil {
		step.AuthID = selected.AuthID
		switch step.Service {
		case "":
			step.Service = selected.AuthType
		case "auth/token":
			switch selected.AuthType {
			case "auth/totp", "auth/radius", "auth/challenge":
				step.Service = selected.AuthType
			case "auth/token":
				if selected.SubType == "totp" {
					step.Service = "auth/totp"
				}
			}
		}
	}

	if step.Service == "auth/sendSms" {
		step.Service = "auth/sms"
	}

	// Some older gateways omit authType and only return an authId. This was
	// historically the response shape for SMS secondary authentication.
	if step.Service == "" && step.AuthID != "" {
		step.Service = "auth/sms"
	}

	if step.Service == "auth/sms" {
		if step.AuthID == "" {
			step.SMSMode = smsWithoutAuthID
		} else {
			step.SMSMode = smsWithAuthID
		}
	}

	return step
}

func (s *Session) authCheck() (authStep, error) {

	u := s.baseURL + "/passport/v1/auth/authCheck"
	req, _ := http.NewRequest("GET", u+"?"+WithSharedParams(nil).Encode(), nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.request(req)
	if err != nil {
		return authStep{}, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)

	var ac struct {
		Code    int          `json:"code"`
		Message string       `json:"message"`
		Data    authStepData `json:"data"`
	}
	err = json.Unmarshal(body, &ac)
	if err != nil {
		return authStep{}, err
	}

	if ac.Code != 0 {
		return authStep{}, fmt.Errorf("authCheck failed with code %d: %s", ac.Code, ac.Message)
	}

	return authStepFromData(ac.Data), nil
}

func (s *Session) phoneNumber(authID string) ([]string, error) {

	u := s.baseURL + "/passport/v1/public/phoneNumber"
	params := WithSharedParams(nil)
	if authID != "" {
		params.Set("authId", authID)
	}
	req, _ := http.NewRequest("GET", u+"?"+params.Encode(), nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.request(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)

	var re struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			PhoneNumber         json.RawMessage `json:"phoneNumber"`
			MaskIdentifierValue string          `json:"maskIdentifierValue"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &re); err != nil {
		return nil, err
	}
	if re.Code != 0 {
		return nil, fmt.Errorf("phoneNumber failed with code %d: %s", re.Code, re.Message)
	}

	phoneNumbers, err := parsePhoneNumbers(re.Data.PhoneNumber)
	if err != nil {
		return nil, err
	}
	if len(phoneNumbers) == 0 && re.Data.MaskIdentifierValue != "" {
		phoneNumbers = append(phoneNumbers, re.Data.MaskIdentifierValue)
	}
	return phoneNumbers, nil
}

func parsePhoneNumbers(raw json.RawMessage) ([]string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}

	if raw[0] == '[' {
		var phoneNumbers []string
		if err := json.Unmarshal(raw, &phoneNumbers); err != nil {
			return nil, fmt.Errorf("parse phoneNumber list: %w", err)
		}
		return phoneNumbers, nil
	}

	var phoneNumber string
	if err := json.Unmarshal(raw, &phoneNumber); err != nil {
		return nil, fmt.Errorf("parse phoneNumber: %w", err)
	}
	if phoneNumber == "" {
		return nil, nil
	}
	return []string{phoneNumber}, nil
}

func (s *Session) authSms(step authStep) error {

	u := s.baseURL + "/passport/v1/auth/sms"
	params := WithSharedParams(url.Values{
		"action": {"sendsms"},
	})
	switch step.SMSMode {
	case smsWithAuthID:
		if step.AuthID == "" {
			return fmt.Errorf("SMS authentication requires authId")
		}
		params.Set("isPrevEffect", "0")
		params.Set("taskId", "")
		params.Set("authId", step.AuthID)
	case smsWithoutAuthID:
		// The stateful SMS flow does not use authId.
	default:
		return fmt.Errorf("unknown SMS authentication mode")
	}
	req, _ := http.NewRequest("GET", u+"?"+params.Encode(), nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.request(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)

	var re struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Tips string `json:"tips"`
		}
	}
	err = json.Unmarshal(body, &re)
	if err != nil {
		return err
	}

	if re.Code != 0 && re.Code != 75500401 {

		return fmt.Errorf("authSms failed with code %d: %s", re.Code, re.Message)
	}

	return nil
}

func (s *Session) smsCheckCode(step authStep) (authStep, error) {

	challenge := authchallenge.CodeChallenge{
		Kind:                 authchallenge.CodeSMS,
		Message:              "Please enter the SMS verification code:",
		CanSkipSecondaryAuth: true,
	}
	response, err := s.challengeHandler.HandleCodeChallenge(challenge)
	if err != nil {
		return authStep{}, fmt.Errorf("complete secondary SMS challenge: %w", err)
	}
	return s.secondarySMSCheckCodeImpl(step, response.Code, response.SkipSecondaryAuth)
}

func (s *Session) secondarySMSCheckCodeImpl(step authStep, code string, skipSecondaryAuth bool) (authStep, error) {
	u := s.baseURL + "/passport/v1/auth/sms"
	params := WithSharedParams(url.Values{
		"action": {"checkcode"},
	})

	skipSecondaryAuthStr := "0"
	if skipSecondaryAuth {
		skipSecondaryAuthStr = "1"
	}

	var req *http.Request
	switch step.SMSMode {
	case smsWithoutAuthID:
		form := url.Values{
			"code":              {code},
			"skipSecondaryAuth": {skipSecondaryAuthStr},
		}
		req, _ = http.NewRequest("POST", u+"?"+params.Encode(), strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case smsWithAuthID:
		if step.AuthID == "" {
			return authStep{}, fmt.Errorf("SMS authentication requires authId")
		}
		payload := map[string]any{
			"isPrevEffect":      false,
			"code":              code,
			"skipSecondaryAuth": skipSecondaryAuthStr,
			"taskId":            "",
			"authId":            step.AuthID,
		}
		bdy, _ := json.Marshal(payload)
		req, _ = http.NewRequest("POST", u+"?"+params.Encode(), bytes.NewReader(bdy))
		req.Header.Set("Content-Type", "application/json;charset=utf-8")
	default:
		return authStep{}, fmt.Errorf("unknown SMS authentication mode")
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.request(req)
	if err != nil {
		return authStep{}, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)

	var re struct {
		Code    int          `json:"code"`
		Message string       `json:"message"`
		Data    authStepData `json:"data"`
	}
	err = json.Unmarshal(body, &re)
	if err != nil {
		return authStep{}, err
	}

	if re.Code != 0 {

		return authStep{}, fmt.Errorf("smsCheckCode failed with code %d: %s", re.Code, re.Message)
	}

	return authStepFromData(re.Data), nil
}

func (s *Session) onlineInfo() (string, error) {

	u := s.baseURL + "/passport/v1/user/onlineInfo"
	req, _ := http.NewRequest("GET", u+"?"+WithSharedParams(nil).Encode(), nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.request(req)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)

	var re struct {
		Code int `json:"code"`
		Data struct {
			Username string `json:"username"`
		}
	}

	err = json.Unmarshal(body, &re)
	if err != nil {
		return "", err
	}

	if re.Code != 0 {

		return "", fmt.Errorf("onlineInfo failed with code %d", re.Code)
	}

	return re.Data.Username, nil
}

func (s *Session) ClientResource() ([]byte, error) {

	u := s.baseURL + "/controller/v1/user/clientResource"
	payload := map[string]interface{}{
		"resourceType": map[string]interface{}{
			"sdpPolicy":       struct{}{},
			"appList":         struct{}{},
			"favoriteAppList": struct{}{},
			"featureCenter":   struct{}{},
			"uemSpace": map[string]interface{}{
				"params": map[string]string{"action": "login"},
			},
		},
	}
	bdy, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", u+"?"+WithSharedParams(nil).Encode(), bytes.NewReader(bdy))
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.request(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)

	return body, nil
}

func (s *Session) checkCode() ([]byte, error) {

	u := s.baseURL + "/passport/v1/public/checkCode"
	params := WithSharedParams(url.Values{
		"rnd": {strconv.FormatInt(time.Now().UnixMilli(), 10)},
	})
	req, _ := http.NewRequest("GET", u+"?"+params.Encode(), nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "image/webp,image/apng,image/*,*/*;q=0.8")

	resp, err := s.request(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)

	return body, nil
}

func parsePortalTicketFromRedirect(redirectLocation, baseHost string) (string, error) {
	redirectURL, err := parseAuthCallback("https://"+baseHost, redirectLocation, "/portal/shortcut.html", "data")
	if err != nil {
		return "", err
	}
	queries := redirectURL.Query()

	var tk struct {
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal([]byte(queries.Get("data")), &tk); err != nil {
		return "", err
	}

	if tk.Ticket == "" {
		return "", fmt.Errorf("invalid portal data: ticket not found")
	}
	return tk.Ticket, nil
}
