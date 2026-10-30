// Package testmihomo provides owned controller processes. Production must not import it.
package testmihomo

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type Options struct {
	Transport                    string
	TunEnabled                   bool
	TunDevice, OutboundInterface string
	Redirect                     string
	Oversize                     bool
}
type Facts struct{ Address, IPC, Secret string }
type Fixture struct {
	Options
	Facts
	PID           int
	Configuration string
	DNS           string
}

func Start(t testing.TB, options Options) *Fixture {
	t.Helper()
	directory, err := os.MkdirTemp("", "jcm-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(directory) })
	name := "mihomo"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(directory, name)
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	output, err := os.OpenFile(binary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		input.Close()
		t.Fatal(err)
	}
	_, err = io.Copy(output, input)
	input.Close()
	output.Close()
	if err != nil {
		t.Fatal(err)
	}
	configuration := filepath.Join(directory, "config.json")
	data, _ := json.Marshal(options)
	if err = os.WriteFile(configuration, data, 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "-f", configuration)
	command.Env = append(os.Environ(), "JC_MIHOMO_TEST_HELPER=1")
	reader, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	control, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	t.Cleanup(func() {
		control.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("owned controller exit: %v", err)
			}
		case <-time.After(5 * time.Second):
			command.Process.Kill()
			<-done
			t.Error("owned controller did not release its listeners")
		}
	})
	var facts Facts
	ready := make(chan error, 1)
	go func() { ready <- json.NewDecoder(reader).Decode(&facts) }()
	select {
	case err = <-ready:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("owned controller readiness deadline")
	}
	return &Fixture{Options: options, Facts: facts, PID: command.Process.Pid, Configuration: configuration}
}

func (f *Fixture) Counts(t testing.TB) (queries, cancelled int) {
	t.Helper()
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true}
	client := &http.Client{Transport: transport, Timeout: time.Second}
	defer client.CloseIdleConnections()
	request, _ := http.NewRequest(http.MethodGet, "http://"+f.Address+"/counts", nil)
	request.Header.Set("Authorization", "Bearer "+f.Secret)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var result struct{ Queries, Cancelled int }
	if json.NewDecoder(response.Body).Decode(&result) != nil {
		t.Fatal("owned counters unavailable")
	}
	return result.Queries, result.Cancelled
}

// Run dispatches before testing parses flags, so the child has an actual Mihomo-style command line.
func Run() bool {
	if os.Getenv("JC_MIHOMO_TEST_HELPER") != "1" {
		return false
	}
	if len(os.Args) != 3 || os.Args[1] != "-f" {
		panic("invalid owned controller command")
	}
	configuration := os.Args[2]
	data, err := os.ReadFile(configuration)
	if err != nil {
		panic(err)
	}
	var options Options
	if json.Unmarshal(data, &options) != nil {
		panic("invalid fixture options")
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	facts := Facts{Address: tcp.Addr().String(), Secret: rand.Text()}
	settings := map[string]any{"external-controller": facts.Address, "secret": facts.Secret}
	var ipc net.Listener
	if options.Transport != "tcp" {
		facts.IPC = ipcName(filepath.Dir(configuration))
		ipc, err = listenIPC(facts.IPC)
		if err != nil {
			panic(err)
		}
		key := "external-controller-unix"
		if runtime.GOOS == "windows" {
			key = "external-controller-pipe"
		}
		settings[key] = facts.IPC
	}
	data, _ = json.Marshal(settings)
	if err = os.WriteFile(configuration, data, 0600); err != nil {
		panic(err)
	}
	var queries, cancelled atomic.Int32
	handler := func(authenticate bool) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if authenticate && r.Header.Get("Authorization") != "Bearer "+facts.Secret {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			switch r.URL.Path {
			case "/version":
				if options.Redirect != "" {
					http.Redirect(w, r, options.Redirect, http.StatusFound)
					return
				}
				padding := ""
				if options.Oversize {
					padding = strings.Repeat("x", 2<<20)
				}
				json.NewEncoder(w).Encode(map[string]any{"meta": true, "version": "owned-fixture", "padding": padding})
			case "/configs":
				json.NewEncoder(w).Encode(map[string]any{"port": 0, "socks-port": 0, "mixed-port": 0, "interface-name": options.OutboundInterface, "tun": map[string]any{"enable": options.TunEnabled, "device": options.TunDevice}})
			case "/counts":
				json.NewEncoder(w).Encode(map[string]int32{"Queries": queries.Load(), "Cancelled": cancelled.Load()})
			case "/dns/query":
				queries.Add(1)
				name := r.URL.Query().Get("name")
				kind := r.URL.Query().Get("type")
				if strings.HasPrefix(name, "stall.") {
					<-r.Context().Done()
					cancelled.Add(1)
					return
				}
				if strings.HasPrefix(name, "nostatus.") {
					io.WriteString(w, `{"Answer":[]}`)
					return
				}
				typeNumber := 1
				address := "127.0.0.1"
				if kind == "AAAA" {
					typeNumber = 28
					address = "::1"
				}
				if strings.HasPrefix(name, "invalid.") {
					address = "not an IP"
				}
				alias := "resolved." + name
				json.NewEncoder(w).Encode(map[string]any{"Status": 0, "RD": true, "RA": true, "Answer": []any{map[string]any{"name": name, "type": 5, "TTL": 37, "data": alias}, map[string]any{"name": alias, "type": typeNumber, "TTL": 37, "data": address}}})
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		})
	}
	server := &http.Server{Handler: handler(true)}
	serve := func(server *http.Server, listener net.Listener) {
		if err := server.Serve(listener); err != http.ErrServerClosed {
			panic(err)
		}
	}
	go serve(server, tcp)
	var ipcServer *http.Server
	if ipc != nil {
		ipcServer = &http.Server{Handler: handler(false)}
		go serve(ipcServer, ipc)
	}
	json.NewEncoder(os.Stdout).Encode(facts)
	io.Copy(io.Discard, os.Stdin)
	server.Close()
	if ipcServer != nil {
		ipcServer.Close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	server.Shutdown(ctx)
	if ipcServer != nil {
		ipcServer.Shutdown(ctx)
	}
	return true
}
