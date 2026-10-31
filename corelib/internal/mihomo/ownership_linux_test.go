//go:build linux

package mihomo

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestPrivilegedListenerOwnership(t *testing.T) {
	if os.Getenv("JC_OWNED_MIHOMO_PID") == "" {
		t.Skip("requires the private privileged Mihomo fixture")
	}
	pid, err := strconv.Atoi(os.Getenv("JC_OWNED_MIHOMO_PID"))
	if err != nil || os.Geteuid() == 0 {
		t.Fatal("requires the owned privileged fixture and an ordinary caller")
	}
	list, err := Processes(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, process := range list {
		if process.PID != pid {
			continue
		}
		controller, err := Inspect(t.Context(), process)
		if err != nil {
			t.Fatal("controller", err)
		}
		defer controller.Close()
		unverified, err := controller.ObserveProxy(t.Context())
		if err != nil || unverified.Proxy != nil || unverified.ListenerRequest == nil {
			t.Fatal("ordinary observer did not expose the privileged ownership gap", err)
		}
		t.Log("listening data socket is present, but the ordinary caller cannot inspect the privileged fd table")
		var proofs []ListenerProof
		if value := os.Getenv("JC_LISTENER_PROOFS"); value != "" {
			if err := json.Unmarshal([]byte(value), &proofs); err != nil {
				t.Fatal(err)
			}
		}
		state, err := controller.ObserveProxy(t.Context(), proofs...)
		t.Logf("native controller PID %d; ordinary uid %d; verified data endpoints %v; compatible proxy %v; error %v", pid, os.Geteuid(), state.Endpoints, state.Proxy != nil, err)
		if err != nil || state.Proxy == nil {
			t.Fatal("privileged controller data listener was not verified")
		}
		connection, err := state.Proxy.DialContext(t.Context(), "tcp", os.Getenv("JC_OWNED_ECHO"))
		if err != nil {
			t.Fatal("verified privileged proxy data connection", err)
		}
		payload := []byte("owned privileged proxy payload")
		connection.SetDeadline(time.Now().Add(time.Second))
		if _, err := connection.Write(payload); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, len(payload))
		if _, err := io.ReadFull(connection, reply); err != nil || !bytes.Equal(reply, payload) {
			t.Fatal("privileged proxy lost payload", err)
		}
		connection.Close()
		// Only the fixture PID supplied by the root namespace launcher may be changed.
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPatch, "http://localhost/configs", bytes.NewBufferString(`{"mixed-port":0}`))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := controller.http.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != http.StatusNoContent {
			t.Fatal("fixture listener did not retire", response.StatusCode)
		}
		foreign, err := net.Listen("tcp", state.Proxy.address.String())
		if err != nil {
			t.Fatal("replace only the retired fixture listener", err)
		}
		defer foreign.Close()
		if connection, err := state.Proxy.DialContext(t.Context(), "tcp", os.Getenv("JC_OWNED_ECHO")); err == nil {
			connection.Close()
			t.Fatal("stale root proof trusted a foreign replacement listener")
		}
		foreign.(*net.TCPListener).SetDeadline(time.Now().Add(25 * time.Millisecond))
		if connection, err := foreign.Accept(); err == nil {
			connection.Close()
			t.Fatal("foreign listener received a connection before ownership rejection")
		}
		t.Log("real data returned through the privileged proxy; a foreign same-port replacement was rejected before connect")
		return
	}
	t.Fatal("owned controller was not discovered")
}
