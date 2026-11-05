package auth

import (
	"fmt"

	"github.com/wtalioy/JustConnect/corelib/client/authchallenge"
)

type SMSLogin struct {
	Phone  string
	Domain string
}

func (m SMSLogin) AuthType() string {
	return "auth/smsCheckCode"
}

func (m SMSLogin) LoginDomain() string {
	return m.Domain
}

func (m SMSLogin) login(s *Session, _ AuthInfo) error {
	if err := s.loginAuthSmsCheckCode(m.Phone, m.Domain); err != nil {
		return err
	}
	s.username = smsUsername(m.Phone, m.Domain)
	return nil
}

func smsUsername(phone, domain string) string {
	return phone + "@" + domain
}

func (s *Session) loginAuthSmsCheckCode(phone, loginDomain string) error {
	sendSmsProcess := func(graphCheckCode string) (int, error) {
		return s.sendSms(phone, loginDomain, graphCheckCode)
	}
	err := s.withGraphCheckCode(sendSmsProcess)
	if err != nil {
		return err
	}

	challenge := authchallenge.CodeChallenge{
		Kind: authchallenge.CodeSMS,
	}
	response, err := s.challengeHandler.HandleCodeChallenge(challenge)
	if err != nil {
		return fmt.Errorf("complete primary SMS challenge: %w", err)
	}
	smsCheckCodeProcess := func(graphCheckCode string) (int, error) {
		return s.smsCheckCodeImpl(response.Code, phone, loginDomain, graphCheckCode)
	}
	return s.withGraphCheckCode(smsCheckCodeProcess)
}

func (s *Session) sendSms(phone, loginDomain, graphCheckCode string) (int, error) {

	data := map[string]interface{}{
		"phone":          phone + "@" + loginDomain,
		"graphCheckCode": graphCheckCode,
	}

	var re struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Tips                 string `json:"tips"`
			Interval             string `json:"interval"`
			GraphCheckCodeEnable int    `json:"graphCheckCodeEnable"`
		} `json:"data"`
	}
	err := s.postJSON("/passport/v1/public/sendSms", data, &re)
	if err != nil {
		return 0, err
	}

	if re.Code != 0 {
		if re.Data.GraphCheckCodeEnable == 1 {
			return re.Data.GraphCheckCodeEnable, nil
		}
		return 0, fmt.Errorf("sendSms failed with code %d: %s", re.Code, re.Message)
	}

	return re.Data.GraphCheckCodeEnable, nil
}

func (s *Session) smsCheckCodeImpl(code, phone, loginDomain, graphCheckCode string) (int, error) {

	data := map[string]interface{}{
		"code":  code,
		"phone": phone + "@" + loginDomain,
	}

	if graphCheckCode != "" {
		data["graphCheckCode"] = graphCheckCode
	}

	var re struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Ticket               string `json:"ticket"`
			GraphCheckCodeEnable int    `json:"graphCheckCodeEnable"`
		} `json:"data"`
	}
	err := s.postJSON("/passport/v1/auth/smsCheckCode", data, &re)
	if err != nil {
		return 0, err
	}
	if re.Code != 0 {
		if re.Data.GraphCheckCodeEnable == 1 {
			return re.Data.GraphCheckCodeEnable, nil
		}
		return 0, fmt.Errorf("SMS authentication failed with code %d: %s", re.Code, re.Message)
	}

	if re.Data.Ticket == "" && re.Data.GraphCheckCodeEnable == 0 {
		return 0, fmt.Errorf("SMS authentication succeeded without a ticket")
	}
	s.ticket = re.Data.Ticket

	return re.Data.GraphCheckCodeEnable, nil
}
