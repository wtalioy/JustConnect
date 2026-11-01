package auth

import (
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

type blockingRoundTripper struct{}

func (blockingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, req.Context().Err()
}

func TestNewSessionContextCancelsRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	session := NewSessionContext(ctx, "vpn.example", nil)
	session.client.Transport = blockingRoundTripper{}
	req, err := http.NewRequest(http.MethodGet, "https://example.invalid", nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := session.request(req)
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("request did not observe session cancellation")
	}
}

func TestCancellationInterruptsResponseBody(t *testing.T) {
	for _, source := range []string{"request", "session"} {
		t.Run(source, func(t *testing.T) {
			release := make(chan struct{})
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				<-release
			}))
			defer server.Close()
			defer close(release)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			sessionCtx, requestCtx := context.Background(), context.Background()
			if source == "request" {
				requestCtx = ctx
			} else {
				sessionCtx = ctx
			}
			session := NewSessionContext(sessionCtx, strings.TrimPrefix(server.URL, "https://"), server.Client().Transport.(*http.Transport).TLSClientConfig)
			defer session.client.CloseIdleConnections()
			req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := session.request(req)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			done := make(chan error, 1)
			go func() { _, err := io.ReadAll(response.Body); done <- err }()
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("body error = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("response body did not cancel")
			}
		})
	}
}

func TestAuthenticationResponseBodyIsBoundedAfterDecompression(t *testing.T) {
	const limit = 8 << 20
	for _, compressed := range []bool{false, true} {
		for _, size := range []int{limit, limit + 1} {
			t.Run(fmt.Sprintf("gzip=%t/size=%d", compressed, size), func(t *testing.T) {
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					payload := strings.Repeat("x", size)
					if compressed {
						w.Header().Set("Content-Encoding", "gzip")
						writer := gzip.NewWriter(w)
						io.WriteString(writer, payload)
						writer.Close()
					} else {
						io.WriteString(w, payload)
					}
				}))
				defer server.Close()
				session := newTLSTestSession(server)
				defer session.Close()
				data, err := session.ClientResource()
				if size == limit {
					if err != nil || len(data) != size {
						t.Fatalf("valid boundary rejected: %d, %v", len(data), err)
					}
					return
				}
				var oversized *http.MaxBytesError
				if !errors.As(err, &oversized) || len(data) != limit {
					t.Fatalf("unbounded auth body: bytes=%d, error=%v", len(data), err)
				}
			})
		}
	}
}

func TestAuthenticationActionsRejectTruncatedResponse(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	const payload = `{"code":0,"data":{"username":"student","phoneNumber":["123"],"ticket":"new-ticket"}}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(payload)+1))
		io.WriteString(w, payload)
	}))
	defer server.Close()
	for name, action := range map[string]func(*Session) error{
		"password":      func(s *Session) error { _, err := s.pswImpl("user", "password", "domain", ""); return err },
		"send SMS":      func(s *Session) error { _, err := s.sendSms("123", "domain", ""); return err },
		"SMS code":      func(s *Session) error { _, err := s.smsCheckCodeImpl("123456", "123", "domain", ""); return err },
		"environment":   (*Session).reportEnv,
		"auth check":    func(s *Session) error { _, err := s.authCheck(); return err },
		"phone":         func(s *Session) error { _, err := s.phoneNumber("id"); return err },
		"secondary SMS": func(s *Session) error { return s.authSms(authStep{SMSMode: smsWithoutAuthID}) },
		"secondary code": func(s *Session) error {
			_, err := s.secondarySMSCheckCodeImpl(authStep{SMSMode: smsWithoutAuthID}, "123456", false)
			return err
		},
		"online info": func(s *Session) error { _, err := s.onlineInfo(); return err },
		"resources":   func(s *Session) error { _, err := s.ClientResource(); return err },
		"captcha":     func(s *Session) error { _, err := s.checkCode(); return err },
	} {
		t.Run(name, func(t *testing.T) {
			session := newTLSTestSession(server)
			defer session.Close()
			session.ticket = "existing-ticket"
			session.pubKey, session.pubKeyExp = key.N.Text(16), strconv.Itoa(key.E)
			if err := action(session); !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatalf("truncated response accepted or hidden: %v", err)
			}
			if session.ticket != "existing-ticket" {
				t.Fatal("incomplete response changed the authentication ticket")
			}
		})
	}
}
