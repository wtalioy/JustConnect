package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTLSTestSession(server *httptest.Server) *Session {
	return NewSession(strings.TrimPrefix(server.URL, "https://"), server.Client().Transport.(*http.Transport).TLSClientConfig)
}

func TestAuthenticationRequestUsesCallerKeyLogWriter(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"code":0,"data":{}}`)) }))
	defer server.Close()
	writer := new(strings.Builder)
	policy := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	policy.KeyLogWriter = writer
	session := NewSession(strings.TrimPrefix(server.URL, "https://"), policy)
	defer session.Close()
	if _, err := session.accessCheck(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(writer.String(), "CLIENT_") {
		t.Fatal("authenticated TLS request did not use caller key-log writer")
	}
	if policy.ServerName != "" || policy.InsecureSkipVerify {
		t.Fatal("authentication mutated caller policy")
	}
}
