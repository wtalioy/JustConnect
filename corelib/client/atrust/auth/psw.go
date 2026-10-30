package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
)

type PasswordLogin struct {
	Username string
	Password string
	Domain   string
}

func (m PasswordLogin) AuthType() string {
	return "auth/psw"
}

func (m PasswordLogin) LoginDomain() string {
	return m.Domain
}

func (m PasswordLogin) login(s *Session, _ AuthInfo) error {
	if m.Username == "" || m.Password == "" {
		return ErrCredentialsRequired
	}
	return s.loginAuthPsw(m.Username, m.Password, m.Domain)
}

func (s *Session) loginAuthPsw(username, password, loginDomain string) error {
	process := func(graphCheckCode string) (int, error) {
		return s.pswImpl(username, password, loginDomain, graphCheckCode)
	}
	return s.withGraphCheckCode(process)
}

func (s *Session) pswImpl(username, password, loginDomain, graphCheckCode string) (int, error) {

	encryptedPwd, err := s.encryptAuthSecret(password)
	if err != nil {
		return 0, err
	}

	s.username = username + "@" + loginDomain
	data := map[string]interface{}{
		"username":    s.username,
		"password":    encryptedPwd,
		"rememberPwd": "0",
	}

	if graphCheckCode != "" {
		data["graphCheckCode"] = graphCheckCode
	}
	postBody, _ := json.Marshal(data)

	u := s.baseURL + "/passport/v1/auth/psw"
	req, _ := http.NewRequest("POST", u+"?"+WithSharedParams(nil).Encode(), bytes.NewReader(postBody))
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-env", s.env)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.request(req)
	if err != nil {
		return 0, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)

	var re struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Ticket               string `json:"ticket"`
			GraphCheckCodeEnable int    `json:"graphCheckCodeEnable"`
			NextService          string `json:"nextService"`
			AntiReplayRand       string `json:"antiReplayRand"`
		} `json:"data"`
	}
	err = json.Unmarshal(body, &re)
	if err != nil {
		return 0, err
	}
	if re.Code != 0 {
		if re.Data.GraphCheckCodeEnable == 1 {
			return re.Data.GraphCheckCodeEnable, nil
		}
		return 0, fmt.Errorf("password authentication failed with code %d: %s", re.Code, re.Message)
	}

	if re.Data.Ticket == "" && re.Data.GraphCheckCodeEnable == 0 {
		return 0, fmt.Errorf("password authentication succeeded without a ticket")
	}
	s.ticket = re.Data.Ticket

	s.nextService = re.Data.NextService
	// The server issues a fresh antiReplayRand; the challenge token must use it (stale -> 75500000).
	if re.Data.AntiReplayRand != "" {
		s.antiReplayRand = re.Data.AntiReplayRand
	}

	return re.Data.GraphCheckCodeEnable, nil
}

func encryptPKCS1v15Chunks(pub *rsa.PublicKey, plaintext []byte) ([]byte, error) {
	maxChunkSize := pub.Size() - 11
	if maxChunkSize <= 0 {
		return nil, fmt.Errorf("RSA public key is too small")
	}

	ciphertext := make([]byte, 0, ((len(plaintext)+maxChunkSize-1)/maxChunkSize)*pub.Size())
	for len(plaintext) > 0 {
		chunkSize := min(len(plaintext), maxChunkSize)
		chunk, err := rsa.EncryptPKCS1v15(rand.Reader, pub, plaintext[:chunkSize])
		if err != nil {
			return nil, err
		}
		ciphertext = append(ciphertext, chunk...)
		plaintext = plaintext[chunkSize:]
	}
	return ciphertext, nil
}

// Password and RADIUS challenge secrets share the same nonce and wire encryption.
func (s *Session) encryptAuthSecret(secret string) (string, error) {
	N, ok := new(big.Int).SetString(s.pubKey, 16)
	if !ok {
		return "", fmt.Errorf("invalid RSA public key modulus")
	}
	E, err := strconv.Atoi(s.pubKeyExp)
	if err != nil || E <= 0 {
		return "", fmt.Errorf("invalid RSA public key exponent %q", s.pubKeyExp)
	}
	pub := &rsa.PublicKey{N: N, E: E}
	cipherBytes, err := encryptPKCS1v15Chunks(pub, []byte(secret+"_"+s.antiReplayRand))
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(cipherBytes), nil
}
