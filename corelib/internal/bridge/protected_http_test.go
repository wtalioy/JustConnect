//go:build darwin || windows

package bridge

import (
	"errors"
	"net"
	"net/http"
	"testing"
)

func protectedHTTPPeers(t *testing.T) map[string]string {
	t.Helper()
	urls := make(map[string]string)
	for key, address := range map[string]string{"protected_url": "127.0.0.1:0", "protected_ipv6_url": "[::1]:0"} {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("original-http")) })}
		done := make(chan struct{})
		go func() {
			defer close(done)
			if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
				t.Error("protected HTTP peer stopped unexpectedly", err)
			}
		}()
		t.Cleanup(func() { _ = server.Close(); <-done })
		urls[key] = "http://" + listener.Addr().String()
	}
	return urls
}
