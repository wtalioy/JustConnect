package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestEncryptAuthSecretSpansRSAChunks(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	secret := strings.Repeat("long-password-", 20)
	session := &Session{pubKey: privateKey.N.Text(16), pubKeyExp: strconv.Itoa(privateKey.E), antiReplayRand: "fresh-nonce"}
	plaintext := []byte(secret + "_" + session.antiReplayRand)
	encrypted, err := session.encryptAuthSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := hex.DecodeString(encrypted)
	if err != nil {
		t.Fatal(err)
	}
	blockSize := privateKey.PublicKey.Size()
	if len(ciphertext)%blockSize != 0 || len(ciphertext) <= blockSize {
		t.Fatalf("expected multiple complete RSA blocks, got %d bytes", len(ciphertext))
	}

	decrypted := make([]byte, 0, len(plaintext))
	for offset := 0; offset < len(ciphertext); offset += blockSize {
		chunk, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext[offset:offset+blockSize])
		if err != nil {
			t.Fatal(err)
		}
		decrypted = append(decrypted, chunk...)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatal("decrypted chunks do not match the original plaintext")
	}
}

func TestPswImplReturnsAuthenticationError(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"code":401,"message":"invalid credentials","data":{"graphCheckCodeEnable":0}}`)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	session.pubKey = privateKey.PublicKey.N.Text(16)
	session.pubKeyExp = strconv.Itoa(privateKey.PublicKey.E)
	session.antiReplayRand = "nonce"

	_, err = session.pswImpl("user", "password", "domain", "")
	if err == nil || !strings.Contains(err.Error(), "401: invalid credentials") {
		t.Fatalf("expected authentication error, got %v", err)
	}
}

func TestPswImplPreservesCaptchaChallenge(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"code":401,"message":"captcha required","data":{"graphCheckCodeEnable":1}}`)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	session.pubKey = privateKey.PublicKey.N.Text(16)
	session.pubKeyExp = strconv.Itoa(privateKey.PublicKey.E)
	session.antiReplayRand = "nonce"

	graphCheckCodeEnable, err := session.pswImpl("user", "password", "domain", "")
	if err != nil || graphCheckCodeEnable != 1 {
		t.Fatalf("expected captcha challenge, got flag=%d err=%v", graphCheckCodeEnable, err)
	}
}
